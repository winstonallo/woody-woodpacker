#include "mem.h"
#include "woody.h"
#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static inline int
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
                printf("Patched decryption key %s into payload at position %lu\n", decryption_key_hex, i);
                return 0;
            }
            j++;
        }
        j = 0;
    }
    return 1;
}

static inline bool
overwrite_marker(uint8_t *payload, size_t payload_size, Elf64_Addr entrypoint, uint64_t marker, size_t occurrences) {
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

static inline void
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
get_code_cave(File file, CodeCave *code_cave, const Elf64_Ehdr header, const uint64_t start, const uint64_t end) {
    uint64_t code_cave_biggest_start = 0;
    uint64_t code_cave_biggest_end = 0;

    uint64_t last_section_end = start;
    uint64_t next_section_start;

    const Elf64_Shdr *shdr_table = file.mem + header.e_shoff;

    for (int i = 0; i < header.e_shnum; i++) {
        const Elf64_Shdr *sh = shdr_table + i;

        const uint64_t sh_start = sh->sh_offset;
        const uint64_t sh_end = sh->sh_offset + sh->sh_size;

        if (sh_start >= start && sh_end <= end) {
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
shellcode_overwrite_markers(Payload payload, const Elf64_Ehdr header, const Elf64_Shdr shdr, const Elf64_Phdr phdr) {
    const uint64_t encryption_start = phdr.p_vaddr + (shdr.sh_offset - phdr.p_offset);

    if (inject_xor_key(payload.shellcode.data, payload.shellcode.len, payload.key) != 0) {
        fprintf(stderr, "Could not find stub marker for the XOR decryption key, the shellcode seems to be corrupted.\n");
        return 1;
    }

    if (overwrite_marker(payload.shellcode.data, payload.shellcode.len, header.e_entry, 0x4242424242424242, 1) != 0) {
        fprintf(stderr, "Could not find all occurrences of stub marker for original entrypoint address, the shellcode seems to be corrupted\n");
        return 1;
    }
    printf("Patched entrypoint (0x%lx) into payload\n", header.e_entry);

    if (overwrite_marker(payload.shellcode.data, payload.shellcode.len, header.e_type == ET_DYN, 0x2424242424242424, 1) != 0) {
        fprintf(stderr, "Could not find all occurrences of stub marker for original entrypoint address, the shellcode seems to be corrupted\n");
        return 1;
    }
    printf("Patched shellcode size (%zu bytes) into payload\n", payload.shellcode.len);

    if (overwrite_marker(payload.shellcode.data, payload.shellcode.len, encryption_start, 0x6666666666666666, 3) != 0) {
        fprintf(stderr, "Could not find encryption start marker, the shellcode seems to be corrupted\n");
        return 1;
    }
    printf("Patched start address of section to be encrypted (0x%lx) into payload\n", encryption_start);

    if (overwrite_marker(payload.shellcode.data, payload.shellcode.len, shdr.sh_size, 0x3333333333333333, 3) != 0) {
        fprintf(stderr, "Could not find encryption size marker, the shellcode seems to be corrupted\n");
        return 1;
    }
    printf("Patched size of section to be encrypted (0x%lx) into payload\n", shdr.sh_size);

    print_payload(payload.shellcode.data, payload.shellcode.len);
    return 0;
}
