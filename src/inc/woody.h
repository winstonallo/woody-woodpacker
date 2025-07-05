

#ifndef WOODY_H
#define WOODY_H

#include <elf.h>
#include <sys/types.h>

typedef struct {
    uint64_t start;
    uint64_t size;
} code_cave_t;

int elf64_ident_check(const Elf64_Ehdr *header);
int key_create(int ac, char **av, u_int8_t *key);
int file_duplicate(char **av);
int elf_header_parse(int fd, Elf64_Ehdr *header);
int section_header_entry_get(const Elf64_Ehdr header, Elf64_Shdr *section_header_entry, int fd);
int program_header_by_section_header_get(const Elf64_Ehdr header, const Elf64_Shdr section_header, Elf64_Phdr *program_header_res, int fd);
int program_header_get_next(const Elf64_Ehdr header, const Elf64_Phdr program_header_cur, Elf64_Phdr *program_header_next, int fd);
int code_cave_get(const Elf64_Ehdr header, const uint64_t ph_start, const uint64_t ph_end, code_cave_t *code_cave, int fd);
int shellcode_inject(Elf64_Ehdr header, Elf64_Phdr program_header, const code_cave_t code_cave, uint8_t shellcode[], const uint64_t shellcode_size, int fd,
                     const uint8_t key[16], const uint64_t encryption_start, const uint64_t encryption_size);
int section_text_encrypt(const Elf64_Shdr section_header_entry, int fd, const uint8_t key[16]);

#endif
