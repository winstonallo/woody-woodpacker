#include "stub_bytes.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20 // cant find MAP_ANONYMOUS in sys/mman.h when running on Macs
#endif

typedef struct {
    uint8_t *data;
    size_t len;
    size_t allocated;
} Binary;



void *alloc(size_t size);

int elf64_ident_check(const Elf64_Ehdr *header);

static uint8_t *
_realloc(uint8_t *old, size_t new_size, size_t old_size) {
    uint8_t *new_buf = malloc(new_size * sizeof(uint8_t));
    if (new_buf == NULL) {
        return NULL;
    }

    memcpy(new_buf, old, old_size);
    free(old);

    return new_buf;
}

static Binary
read_file(const char *const path) {
    Binary str = {.data = malloc(1024 * sizeof(uint8_t)), .len = 0, .allocated = 1024};
    if (str.data == NULL) {
        perror("(read_file) Could not allocate:");
        return (Binary){0};
    }

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "(read_file) Could not open '%s': %s", path, strerror(errno));
        return (Binary){0};
    }

    ssize_t bytes_read;
    while ((bytes_read = read(fd, str.data + str.len, str.allocated - str.len)) > 0) {
        str.len += bytes_read;

        if (str.len >= str.allocated) {
            str.allocated *= 2;

            str.data = _realloc(str.data, str.allocated + 1, str.len);
            if (str.data == NULL) {
                fprintf(stderr, "(read_file) Could not reallocate %zu bytes: %s", str.allocated + 1, strerror(errno));
                return (Binary){0};
            }
        }
    }

    if (bytes_read == -1) {
        return (Binary){0};
    }

    str.data[str.len] = '\0';

    return str;
}

int
main(int ac, char **av) {
    if (ac != 2) {
        printf("wrong usage: ./woody BINARY_NAME\n");
        return 1;
    }

    Binary binary = read_file(av[1]);
    if (binary.data == NULL) {
        return 1;
    }

    Elf64_Ehdr *header = (Elf64_Ehdr *)binary.data;
    int err = elf64_ident_check((Elf64_Ehdr *)binary.data);
    if (err) {
        printf("error while checking ident of elf with code: %i\n", err);
        return 1;
    }

    // Find .text section header
    Elf64_Shdr *section_header_text;

    for (int i = 0; i < header->e_shnum; i++) {
        section_header_text = (Elf64_Shdr *)&binary.data[header->e_shoff + (i * sizeof(Elf64_Shdr))];

        if (section_header_text->sh_addr == header->e_entry) break;
    }

    Elf64_Phdr *program_header;
    for (int i = 0; i < header->e_phnum; i++) {
        program_header = (Elf64_Phdr*)&binary.data[header->e_phoff + (i * sizeof(Elf64_Phdr))];

        uint64_t start = program_header->p_vaddr;
        uint64_t end = program_header->p_vaddr + program_header->p_filesz;

        if (start <= header->e_entry && end > header->e_entry) break;
        program_header = 0;
    }

    if (program_header == 0)
    {
        printf("can't find dont'want to write error message");
        return 1;
    }
    





    int f = 0;

    uint64_t next_section_start = 0;
    uint64_t last_section_end = program_header->p_offset;

    uint64_t code_cave_biggest_start = 0;
    uint64_t code_cave_biggest_end = 0;
    for (int i = 0; i < header->e_shnum; i++) {
        Elf64_Shdr *section_header;
        section_header = (Elf64_Shdr *)&binary.data[header->e_shoff + (i * sizeof(Elf64_Shdr))];
        
        uint64_t start = program_header->p_offset;
        uint64_t end = program_header->p_offset + program_header->p_filesz;
        if (f == 1) {
            next_section_start = section_header->sh_offset;
            uint64_t code_cave_size = code_cave_biggest_end - code_cave_biggest_start;
            if (code_cave_size < next_section_start - last_section_end) {
                code_cave_biggest_start = last_section_end;
                code_cave_biggest_end = next_section_start;
            }

            last_section_end = section_header->sh_offset + section_header->sh_size;
            f = 0;
        }else if (section_header->sh_offset >= start && (section_header->sh_offset + section_header->sh_size) <= end) {
            f = 1;
            next_section_start = section_header->sh_offset;
            uint64_t code_cave_size = code_cave_biggest_end - code_cave_biggest_start;
            if (code_cave_size < next_section_start - last_section_end) {
                code_cave_biggest_start = last_section_end;
                code_cave_biggest_end = next_section_start;
            }

            last_section_end = section_header->sh_offset + section_header->sh_size;
        }

    }


    printf("Start %lx\n", code_cave_biggest_start);
    printf("End %lx\n", code_cave_biggest_end);

    // Find the code cave between .text and the next section

    program_header->p_filesz = 0x1000;


    uint64_t shellcode_offset = code_cave_biggest_start + code_cave_biggest_start % 8;
    printf("shellcode offset: %lx\n", shellcode_offset);

    memcpy(binary.data + shellcode_offset, decryption_stub, sizeof(decryption_stub));

    uint64_t shellcode_addr = section_header_text->sh_addr + (shellcode_offset - section_header_text->sh_offset);

    printf("text start  0x%lx\n", section_header_text->sh_addr);
    printf("stub addr   0x%lx\n", section_header_text->sh_addr + section_header_text->sh_size);
    
    // section_header_text->sh_size += sizeof(decryption_stub);
    header->e_entry = shellcode_addr;
    printf("shellcode vaddr %lx\n", shellcode_addr);

    int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("could not create new 'woody' binary:");
        return -1;
    }

    write(fd, binary.data, binary.len);

    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     read(file, &c, 1);
    //     if (c == '7')
    //     {
    //         printf("(%i|%c)\n", i, c);
    //         lseek(file, -1, SEEK_CUR);
    //         write(file, "*", 1);
    //     }
    // }
    // printf("\n");

    // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     c = '*';
    //     write(file, &c, 1);
    //     // read(file, &c, 1);
    //     // if (c == '7')
    //     // {
    //     //     lseek(file, -1, SEEK_CUR);
    //     //     write(file, "8", 1);
    //     //     printf("Changed\n");
    //     // }
    // }
    // printf("----------------\n");

    // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     read(file, &c, 1);
    //     printf("%c", c);
    // }
    // printf("\n");
    // fflush(file);
    free(binary.data);
    return 0;
    // Read an elf binary
    // Check if its a 64 bit elf with the starting values

    // Where does the execution start

    // Read the whole code segment
    // Apply encryption
    // save it to file
    //

    // Add a code segment to elf which decrypts the code segment
    // printf("%p\n", &main);
    // __uint64_t add = &alloc;
    // printf("%p\n", add);
    // add = add - (add % 4096);
    // printf("%p\n", add);
    // int a = mprotect(add, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    // if (a)
    //     return a;
    // int *p = alloc(1);
}

int
elf64_ident_check(const Elf64_Ehdr *header) {
    assert(header);

    if (header->e_ident[EI_MAG0] != ELFMAG0) return 1;
    if (header->e_ident[EI_MAG1] != ELFMAG1) return 1;
    if (header->e_ident[EI_MAG2] != ELFMAG2) return 1;
    if (header->e_ident[EI_MAG3] != ELFMAG3) return 1;

    if (header->e_ident[EI_CLASS] != ELFCLASS64) return 2;

    if (header->e_ident[EI_DATA] == ELFDATANONE) return 3;

    if (header->e_ident[EI_VERSION] != EV_CURRENT) return 4;

    for (int i = EI_PAD; i < sizeof(header); i++) {
        if (header->e_ident[i] != 0) return 5;
    }
    return 0;
}
