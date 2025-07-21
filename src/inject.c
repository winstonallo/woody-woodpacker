#include "inc/utils.h"
#include "inc/woody.h"
#include "unistd.h"
#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "mem.h"

int
inject_xor_key(const uint8_t *shellcode, const size_t shellcode_size, const uint8_t key[16]) {
    const uint8_t marker[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    for (size_t i = 0; i < shellcode_size; ++i) {
        int j = 0;
        while (marker[j] == shellcode[i + j]) {
            if (j == 15) {
                ft_memcpy((uint8_t *)&shellcode[i], key, 16);
                char decryption_key_hex[32];
                for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
                    snprintf(decryption_key_hex + byte_idx * 2, 3, "%02x", key[byte_idx]);
                }
                printf("Injected decryption key %s into payload at position %lu\n", decryption_key_hex, i);
                return 0;
            }
            j++;
        }
        j = 0;
    }
    return 0;
}
bool
overwrite_entrypoint(uint8_t *payload, size_t payload_size, Elf64_Addr entrypoint, uint64_t marker, size_t occurrences) {
    size_t found = 0;

    for (size_t i = 0; i < payload_size - 8; ++i) {
        uint64_t *ptr = (uint64_t *)&payload[i];

        if (*ptr == marker) {
            *ptr = entrypoint;
            found++;
        }

        if (found == occurrences) {
            break;
        }
    }

    return found != occurrences;
}

void
print_payload(uint8_t *payload, size_t payload_size) {
    printf("\n -- Final Payload --\n");
    size_t i;
    for (i = 0; i < payload_size / 16; ++i) {
        for (int j = 0; j < 16; j += 2) {
            printf("0x%02x%02x ", payload[i * 16 + j], payload[i * 16 + j + 1]);
        }
        printf("\n");
    }
    size_t remainder = payload_size % 16;
    for (size_t j = 0; j < remainder; j += 2) {
        printf("0x%02x%02x ", payload[i * 16 + j], payload[i * 16 + j + 1]);
    }
    printf("\n");
}
int
code_cave_get(const Elf64_Ehdr header, const uint64_t ph_start, const uint64_t ph_end, code_cave_t *code_cave, int fd) {
    size_t off = lseek(fd, header.e_shoff, SEEK_SET);
    if (off != header.e_shoff) {
        perror("lseek - fd");
        return 1;
    }

    int bytes_read;

    Elf64_Shdr section_header;

    uint64_t last_section_end = ph_start;
    uint64_t next_section_start;

    uint64_t code_cave_biggest_start = 0;
    uint64_t code_cave_biggest_end = 0;

    for (int i = 0; i < header.e_shnum; i++) {
        bytes_read = read(fd, &section_header, sizeof(Elf64_Shdr));
        if (bytes_read != sizeof(Elf64_Shdr)) {
            perror("read");
            return 1;
        }

        const uint64_t sh_start = section_header.sh_offset;
        const uint64_t sh_end = section_header.sh_offset + section_header.sh_size;

        const uint16_t section_is_inside_program_header = sh_start >= ph_start && sh_end <= ph_end;
        if (section_is_inside_program_header) {
            next_section_start = sh_start;
            uint64_t code_cave_size_cur = next_section_start - last_section_end;

            uint64_t code_cave_biggest_size = code_cave_biggest_end - code_cave_biggest_start;
            if (code_cave_biggest_size < code_cave_size_cur) {
                code_cave_biggest_start = last_section_end;
                code_cave_biggest_end = next_section_start;
            }

            last_section_end = sh_end;
        }
    }

    next_section_start = ph_end;
    uint64_t code_cave_size_cur = next_section_start - last_section_end;

    uint64_t code_cave_biggest_size = code_cave_biggest_end - code_cave_biggest_start;
    if (code_cave_biggest_size < code_cave_size_cur) {
        code_cave_biggest_start = last_section_end;
        code_cave_biggest_end = next_section_start;
    }

    if (code_cave_biggest_end == 0) return 1;

    code_cave->start = code_cave_biggest_start;
    code_cave->size = code_cave_biggest_end - code_cave_biggest_start;
    return 0;
}

int
shellcode_inject(Elf64_Ehdr header, Elf64_Phdr program_header, const code_cave_t code_cave, uint8_t shellcode[], const uint64_t shellcode_size, int fd,
                 const uint8_t key[16], const uint64_t encryption_start, const uint64_t encryption_size) {

    const uint64_t page_size = 0x1000;
    // round down to nearest page boundary for mprotect call (~(page_size - 1) = ~0xfff = 0xFFFFFFFFFFFFF000)
    const uint64_t text_start_aligned = program_header.p_vaddr & ~(page_size - 1);

    inject_xor_key(shellcode, shellcode_size, key);

    if (overwrite_entrypoint(shellcode, shellcode_size, header.e_entry, 0x4242424242424242, 1) != 0) {
        fprintf(stderr, "Could not find all occurrences of stub marker for original entrypoint address, the byte code seems to be corrupted\n");
        return 1;
    }
    printf("Injected original entrypoint (0x%lx) into payload\n", header.e_entry);

    if (overwrite_entrypoint(shellcode, shellcode_size, text_start_aligned, 0x6969696969696969, 1) != 0) {
        fprintf(stderr, "Could not find all occurrences of stub marker for .text section size, the byte code seems to be corrupted\n");
        return 1;
    }
    printf("Injected page-aligned segment of the .text section start address (0x%lx) into payload\n", text_start_aligned);

    if (overwrite_entrypoint(shellcode, shellcode_size, encryption_start, 0x6666666666666666, 1) != 0) {
        fprintf(stderr, "Could not find encryption start marker, the byte code seems to be corrupted");
        return 1;
    }
    printf("Injected start address of section to be encrypted (0x%lx) into payload\n", encryption_start);

    if (overwrite_entrypoint(shellcode, shellcode_size, encryption_size, 0x3333333333333333, 2) != 0) {
        fprintf(stderr, "Could not find encryption size marker, the byte code seems to be corrupted");
        return 1;
    }
    printf("Injected size of section to be encrypted (0x%lx) into payload\n", encryption_size);

    print_payload(shellcode, shellcode_size);

    int off = lseek(fd, code_cave.start, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    size_t bytes_written = write(fd, shellcode, shellcode_size);
    if (bytes_written != shellcode_size) {
        perror("write");
        return 1;
    }

    header.e_entry = program_header.p_vaddr + (code_cave.start - program_header.p_offset);

    off = lseek(fd, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    bytes_written = write(fd, &header, sizeof(Elf64_Ehdr));
    if (bytes_written != sizeof(Elf64_Ehdr)) {
        perror("write");
        return 1;
    }

    if (fd_set_to_ph_offset(fd, header, program_header)) return 1;

    program_header.p_filesz += shellcode_size;
    program_header.p_memsz += shellcode_size;
    write(fd, &program_header, sizeof(Elf64_Phdr));
    return 0;
}
