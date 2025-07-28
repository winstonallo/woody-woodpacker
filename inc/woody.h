

#ifndef WOODY_H
#define WOODY_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct CodeCave {
    uint64_t start;
    uint64_t size;
} CodeCave;

typedef struct File {
    void *mem;
    size_t size;
} File;

typedef struct Payload {
    struct {
        uint8_t *data;
        size_t len;
    } shellcode;
    uint8_t key[16];
} Payload;

typedef enum Elf64IdentCheckResult {
    SUCCESS,
    INVALID_EI_MAG,
    NOT_64_BIT,
    NO_DATA,
    INVALID_VERSION,
    INVALID_PADDING,
} Elf64IdentCheckResult;

int parse_or_generate_key(int ac, char **av, u_int8_t *key);
int duplicate_file(char **av);

const Elf64_Shdr *shdr_get_entry(File file, const Elf64_Ehdr hdr);
Elf64_Phdr *phdr_get_by_shdr(File file, const Elf64_Ehdr hdr, const Elf64_Shdr shdr);
const Elf64_Phdr *phdr_get_next(File file, const Elf64_Ehdr hdr, const Elf64_Phdr phdr);

const char * elf64_ident_check(const Elf64_Ehdr *hdr);

int get_code_cave(File file, CodeCave *cave, const Elf64_Ehdr hdr, const uint64_t start, const uint64_t end);

int shellcode_overwrite_markers(Payload payload, const Elf64_Ehdr hdr, const Elf64_Shdr shdr, const Elf64_Phdr phdr);

void encrypt(File file, const Elf64_Shdr shdr, const uint8_t key[16]);

int file_mmap(const char *file_name, File *file);
int file_munmap(const File file);
int file_write(File file);

int fd_set_to_ph_offset(int fd, const Elf64_Ehdr header, Elf64_Phdr program_header);
int parsehex(const uint8_t *restrict bytes, uint8_t *const restrict out);

#endif
