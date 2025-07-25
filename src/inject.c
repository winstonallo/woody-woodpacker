#include "inc/woody.h"
#include "mem.h"
#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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
code_cave_get(file file, code_cave_t *code_cave, const Elf64_Ehdr header, const uint64_t start, const uint64_t end) {
    uint64_t code_cave_biggest_start = 0;
    uint64_t code_cave_biggest_end = 0;

    uint64_t last_section_end = start;
    uint64_t next_section_start;

    const Elf64_Shdr *section_header_table = file.mem + header.e_shoff;

    for (int i = 0; i < header.e_shnum; i++) {
        const Elf64_Shdr *sh = section_header_table + i;

        const uint64_t sh_start = sh->sh_offset;
        const uint64_t sh_end = sh->sh_offset + sh->sh_size;

        const uint8_t section_is_inside_program_header = sh_start >= start && sh_end <= end;
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

    next_section_start = end;
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
shellcode_overwrite_markers(uint8_t shellcode[], const uint64_t shellcode_size, const Elf64_Ehdr header, const Elf64_Shdr section_header,
                            const Elf64_Phdr program_header, const uint8_t key[16]) {

    const uint64_t encryption_start = program_header.p_vaddr + (section_header.sh_offset - program_header.p_offset);
    const uint64_t encryption_size = section_header.sh_size;
    const uint64_t page_size = 0x1000;
    // round down to nearest page boundary for mprotect call (~(page_size - 1) = ~0xfff = 0xFFFFFFFFFFFFF000)
    const uint64_t text_start_aligned = program_header.p_vaddr & ~(page_size - 1);

    inject_xor_key(shellcode, shellcode_size, key);
    printf("Size of injected shellcode: 0x%lx\n", shellcode_size);

    if (overwrite_entrypoint(shellcode, shellcode_size, header.e_entry, 0x4242424242424242, 0) != 0) {
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

    // temporarily hardcoded, should come from code_cave.start
    const size_t shellcode_start_offset = 0x1171;
    const size_t jmp_instruction_offset = shellcode_start_offset + shellcode_size;
    ssize_t rel_offset = encryption_start - (jmp_instruction_offset + 1);
    if (rel_offset < 0) rel_offset *= -1;

    printf("jmp_instruction_offset: 0x%lx\n", jmp_instruction_offset);
    printf("rel_offset: 0x%lx\n", rel_offset);

    print_payload(shellcode, shellcode_size);
    return 0;
}
