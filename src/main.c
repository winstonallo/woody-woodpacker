#include "../stub_bytes.h"
#include "mem.h"
#include "woody.h"
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
        fprintf(stderr, "Invalid arguments\nUsage: ./woody BINARY_NAME [ENCRYPTION_KEY(16 bytes)]\n");
        return 1;
    }

    Payload payload = {0};
    if (parse_or_generate_key(ac, av, payload.key)) return 1;
    payload.shellcode.data = stub;
    payload.shellcode.len = sizeof(stub);

    File file;
    if (file_mmap(av[1], &file)) return 1;

    Elf64_Ehdr *header = file.mem;
    const char *res = elf64_ident_check(header);
    if (*res != '\0') {
        fprintf(stderr, "Error validating %s: %s\n", av[1], res);
        file_munmap(file);
        return 1;
    }

    const Elf64_Shdr *shdr_entry = shdr_get_entry(file, *header);
    if (shdr_entry == NULL) {
        file_munmap(file);
        return 1;
    }
    printf("Found section header including entry point at 0x%lx - 0x%lx\n", shdr_entry->sh_offset, shdr_entry->sh_offset + shdr_entry->sh_size);

    Elf64_Phdr *phdr_entry = phdr_get_by_shdr(file, *header, *shdr_entry);
    if (phdr_entry == NULL) {
        file_munmap(file);
        return 1;
    }
    printf("Found program header of entry point section header at 0x%lx - 0x%lx\n", phdr_entry->p_offset, phdr_entry->p_offset + phdr_entry->p_filesz);

    const Elf64_Phdr *next_phdr = phdr_get_next(file, *header, *phdr_entry);
    if (next_phdr == NULL) {
        file_munmap(file);
        return 1;
    }
    printf("Found next program header 0x%lx\n", next_phdr->p_offset);

    CodeCave cave;
    if (get_code_cave(file, &cave, *header, phdr_entry->p_offset, next_phdr->p_offset)) {
        file_munmap(file);
        return 1;
    }
    if (cave.size < sizeof(stub)) {
        fprintf(stderr, "Biggest code cave found (%zu bytes) too small for stub (%zu bytes) - this binary cannot be packed\n", cave.size, sizeof(stub));
        file_munmap(file);
        return 1;
    }
    printf("Found biggest code cave from 0x%lx - 0x%lx\n", cave.start, cave.start + cave.size);

    printf("\n");
    if (shellcode_overwrite_markers(payload, *header, *shdr_entry, *phdr_entry)) {
        file_munmap(file);
        return 1;
    }

    ft_memcpy(file.mem + cave.start, stub, sizeof(stub));
    printf("\nInjected patched shellcode into binary at offset 0x%lx\n", cave.start);

    header->e_entry = phdr_entry->p_vaddr + (cave.start - phdr_entry->p_offset);
    phdr_entry->p_filesz += sizeof(stub);
    phdr_entry->p_memsz += sizeof(stub);

    encrypt(file, *shdr_entry, payload.key);

    if (file_write(file)) {
        file_munmap(file);
        return 1;
    }
    file_munmap(file);
    return 0;
}
