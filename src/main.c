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
#include <string.h>
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

    file file;
    const char *binary_name = av[1];
    if (file_mmap(binary_name, &file)) return 1;

    Elf64_Ehdr *header = file.mem;

    if (elf64_ident_check(header)) {
        file_munmap(file);
        return 1;
    }

    const Elf64_Shdr *section_header_entry = section_header_entry_get(file, *header);
    if (section_header_entry == NULL) {
        file_munmap(file);
        return 1;
    }

    printf("Found section header which includes the entry point: 0x%lx - 0x%lx\n", section_header_entry->sh_offset,
           section_header_entry->sh_offset + section_header_entry->sh_size);

    Elf64_Phdr *program_header_entry = program_header_by_section_header_get(file, *header, *section_header_entry);
    if (program_header_entry == NULL) {
        file_munmap(file);
        return 1;
    }
    printf("Found program header which includes the section header: 0x%lx - 0x%lx\n", program_header_entry->p_offset,
           program_header_entry->p_offset + program_header_entry->p_filesz);

    const Elf64_Phdr *program_header_after_entry = program_header_get_after(file, *header, *program_header_entry);
    if (program_header_after_entry == NULL) {
        file_munmap(file);
        return 1;
    }
    printf("Found closest program header to the entry one for finding the codecave - starts at 0x%lx\n", program_header_after_entry->p_offset);

    code_cave_t code_cave;
    if (code_cave_get(file, &code_cave, *header, program_header_entry->p_offset, program_header_after_entry->p_offset)) {
        file_munmap(file);
        return 1;
    }
    printf("Found biggest code cave from 0x%lx - 0x%lx\n", code_cave.start, code_cave.start + code_cave.size);

    if (shellcode_overwrite_markers(decryption_stub, sizeof(decryption_stub), *header, *section_header_entry, *program_header_entry, key)) {
        file_munmap(file);
        return 1;
    }

    memcpy(file.mem + code_cave.start, decryption_stub, sizeof(decryption_stub));

    header->e_entry = program_header_entry->p_vaddr + (code_cave.start - program_header_entry->p_offset);

    program_header_entry->p_filesz += sizeof(decryption_stub);
    program_header_entry->p_memsz += sizeof(decryption_stub);

    section_text_encrypt(file, *section_header_entry, key);

    if (file_write(file)) {
        file_munmap(file);
        return 1;
    }
    file_munmap(file);
    return 0;
}
