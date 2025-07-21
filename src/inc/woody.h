

#ifndef WOODY_H
#define WOODY_H

#include <elf.h>
#include <sys/types.h>

typedef struct {
    uint64_t start;
    uint64_t size;
} code_cave_t;

typedef struct {
    void *mem;
    size_t size;
} file;

int elf64_ident_check(const Elf64_Ehdr *header);
int key_create(int ac, char **av, u_int8_t *key);
int file_duplicate(char **av);
const Elf64_Shdr *section_header_entry_get(file file, const Elf64_Ehdr header);
int elf64_ident_check(const Elf64_Ehdr *header);
Elf64_Phdr *program_header_by_section_header_get(file file, const Elf64_Ehdr header, const Elf64_Shdr section_header);
const Elf64_Phdr *program_header_get_after(file file, const Elf64_Ehdr header, const Elf64_Phdr program_header);
int code_cave_get(file file, code_cave_t *code_cave, const Elf64_Ehdr header, const uint64_t start, const uint64_t end);
int shellcode_overwrite_markers(uint8_t shellcode[], const uint64_t shellcode_size, const Elf64_Ehdr header, const Elf64_Shdr section_header,
                                const Elf64_Phdr program_header, const uint8_t key[16]);
int shellcode_inject(Elf64_Ehdr header, Elf64_Phdr program_header, const code_cave_t code_cave, uint8_t shellcode[], const uint64_t shellcode_size, int fd,
                     const uint8_t key[16], const uint64_t encryption_start, const uint64_t encryption_size);
void section_text_encrypt(file file, const Elf64_Shdr section_header, const uint8_t key[16]);
int file_mmap(const char *file_name, file *file);
int file_munmap(const file file);
int file_write(file file);
#endif
