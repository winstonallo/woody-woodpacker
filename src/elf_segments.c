#include "inc/utils.h"
#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include "str.h"
#include <unistd.h>

int
program_header_by_section_header_get(const Elf64_Ehdr header, const Elf64_Shdr section_header, Elf64_Phdr *program_header_res, int fd) {
    assert(program_header_res != NULL);

    size_t off = lseek(fd, header.e_phoff, SEEK_SET);
    if (off != header.e_phoff) {
        perror("lseek - fd");
        return 1;
    }

    const uint64_t sh_start = section_header.sh_offset;
    const uint64_t sh_end = section_header.sh_offset + section_header.sh_size;

    Elf64_Phdr ph;
    for (int i = 0; i < header.e_phnum; i++) {
        int bytes_read = read(fd, &ph, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read");
            return 1;
        }

        const uint64_t ph_start = ph.p_offset;
        const uint64_t ph_end = ph.p_offset + ph.p_filesz;

        const uint16_t section_is_inside_program_header = sh_start >= ph_start && sh_end <= ph_end;
        if (section_is_inside_program_header) {
            *program_header_res = ph;
            return 0;
        }
    }

    char *error = "could not find program header with section header inside";
    write(STDOUT_FILENO, error, ft_strlen(error));
    return 2;
}

int
program_header_get_next(const Elf64_Ehdr header, const Elf64_Phdr program_header_cur, Elf64_Phdr *program_header_next, int fd) {
    assert(program_header_next != NULL);

    size_t off = lseek(fd, header.e_phoff, SEEK_SET);
    if (off != header.e_phoff) {
        perror("lseek - fd");
        return 1;
    }

    int bytes_read;
    Elf64_Phdr program_header;

    Elf64_Phdr program_header_closest = {0};

    for (int i = 0; i < header.e_phnum; i++) {
        bytes_read = read(fd, &program_header, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read");
            return 1;
        }

        if (program_header_cur.p_offset < program_header.p_offset) {
            if (program_header_closest.p_filesz == 0) {
                program_header_closest = program_header;
                continue;
            }

            uint64_t distance = program_header.p_offset - program_header_cur.p_offset;
            uint64_t distance_cur = program_header_closest.p_offset - program_header_cur.p_offset;
            if (distance < distance_cur) program_header_closest = program_header;
        }
    }

    if (program_header_closest.p_filesz == 0) {
        char *error = "could not find program header after current one";
        write(STDOUT_FILENO, error, ft_strlen(error));
        return 2;
    }

    *program_header_next = program_header_closest;
    return 0;
}
