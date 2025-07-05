#include "../stub_bytes.h"
#include "inc/woody.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

int
main(int ac, char **av) {
    if (ac != 2 && ac != 3) {
        printf("wrong usage: ./woody BINARY_NAME [ENCRYPTION_KEY(16 bytes)]\n");
        return 1;
    }

    const uint8_t key[16] = {0};
    if (key_create(ac, av, (u_int8_t *)key)) return 1;

    int file = file_duplicate(av);
    if (file == -1) return 1;

    Elf64_Ehdr header;
    if (elf_header_parse(file, &header)) return 1;

    Elf64_Shdr section_header_entry;

    if (section_header_entry_get(header, &section_header_entry, file)) return 1;

    Elf64_Phdr program_header_entry;
    if (program_header_by_section_header_get(header, section_header_entry, &program_header_entry, file)) return 1;

    Elf64_Phdr program_header_entry_next;
    if (program_header_get_next(header, program_header_entry, &program_header_entry_next, file)) return 1;

    code_cave_t code_cave;
    if (code_cave_get(header, program_header_entry.p_offset, program_header_entry_next.p_offset, &code_cave, file)) return 1;

    const uint64_t encrytion_start = program_header_entry.p_vaddr + (section_header_entry.sh_offset - program_header_entry.p_offset);

    if (shellcode_inject(header, program_header_entry, code_cave, decryption_stub, sizeof(decryption_stub), file, key, encrytion_start,
                         section_header_entry.sh_size)) {
        return 1;
    }

    if (section_text_encrypt(section_header_entry, file, key)) return 1;

    close(file);
}
