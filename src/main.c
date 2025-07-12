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
file_mmap(const char *file_name, file *file) {
    assert(file_name != NULL);
    assert(file != NULL);

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        perror(file_name);
        return -1;
    }

    int off = lseek(fd, 0, SEEK_END);
    if (off == -1) {
        close(fd);
        perror(file_name);
        return -1;
    }
    file->size = off;

    off = lseek(fd, 0, SEEK_SET);
    if (off != 0) {
        close(fd);
        perror(file_name);
        return -1;
    }

    file->mem = mmap(NULL, file->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (file->mem == NULL) {
        perror("mem");
        return -1;
    }

    return 0;
}

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

    if (elf64_ident_check(header)) return 1;

    const Elf64_Shdr *section_header_entry = section_header_entry_get(file, *header);
    if (section_header_entry == NULL) return 1;
    printf("Found section header which includes the entry point: 0x%lx - 0x%lx\n", section_header_entry->sh_offset,
           section_header_entry->sh_offset + section_header_entry->sh_size);

    const Elf64_Phdr *program_header_entry = program_header_by_section_header_get(file, *header, *section_header_entry);
    if (program_header_entry == NULL) return 1;
    printf("Found program header which includes the section header: 0x%lx - 0x%lx\n", program_header_entry->p_offset,
           program_header_entry->p_offset + program_header_entry->p_filesz);

    const Elf64_Phdr *program_header_after_entry = program_header_get_after(file, *header, *program_header_entry);
    if (program_header_after_entry == NULL) return 1;
    printf("Found closest program header to the entry one for finding the codecave - starts at 0x%lx\n", program_header_after_entry->p_offset);

    code_cave_t code_cave;
    if (code_cave_get(file, &code_cave, *header, program_header_entry->p_offset, program_header_after_entry->p_offset)) return 1;
    printf("Found biggest code cave from 0x%lx - 0x%lx\n", code_cave.start, code_cave.start + code_cave.size);

    const uint64_t encrytion_start = program_header_entry->p_vaddr + (section_header_entry->sh_offset - program_header_entry->p_offset);

    // if (shellcode_inject(*header, *program_header_entry, code_cave, decryption_stub, sizeof(decryption_stub), file, key, encrytion_start,
    //                      section_header_entry.sh_size)) return 1;
    //     close(file);
    //     return 1;
    // }

    // if (section_text_encrypt(section_header_entry, file, key)) {
    //     close(file);
    //     return 1;
    // }

    // close(file);
}
