#include "stub_bytes.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

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

    for (int i = EI_PAD; i < sizeof(header->e_ident); i++) {
        if (header->e_ident[i] != 0) return 5;
    }
    return 0;
}

int
put_str(int fd, char *str) {
    int bytes_written = write(fd, str, strlen(str));
    if (bytes_written != strlen(str)) return 1;
    return 0;
}

int
fd_copy_whole(int fd_dest, int fd_src) {

    int bytes_read;
    int bytes_written;

    int off = lseek(fd_src, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_src");
        return 1;
    }

    char buf[100];
    do {
        bytes_read = read(fd_src, &buf, sizeof(buf));
        if (bytes_read == -1) {
            perror("read - fd_src");
            return 1;
        }
        bytes_written = write(fd_dest, &buf, bytes_read);
        if (bytes_written == -1) {
            perror("write - fd_dest");
            return 1;
        }
    } while (bytes_read == sizeof(buf));

    return 0;
}

int
section_header_entry_get(const Elf64_Ehdr header, Elf64_Shdr *section_header_entry, int fd) {
    assert(section_header_entry != NULL);

    int off = lseek(fd, header.e_shoff, SEEK_SET);
    if (off != header.e_shoff) {
        perror("lseek - section_header_entry_get fd");
        return 1;
    }

    Elf64_Shdr sh;
    for (int i = 0; i < header.e_shnum; i++) {
        int bytes_read = read(fd, &sh, sizeof(Elf64_Shdr));
        if (bytes_read != sizeof(Elf64_Shdr)) {
            perror("read");
            return 1;
        }

        if (sh.sh_addr == header.e_entry) {
            *section_header_entry = sh;
            return 0;
        }
    }

    put_str(STDERR_FILENO, "could not find section header that is pointed to by e_entry");
    return 2;
}

int
program_header_by_section_header_get(const Elf64_Ehdr header, const Elf64_Shdr section_header, Elf64_Phdr *program_header_res, int fd) {
    assert(program_header_res != NULL);

    int off = lseek(fd, header.e_phoff, SEEK_SET);
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
    write(STDOUT_FILENO, error, strlen(error));
    return 2;
}

typedef struct {
    uint64_t start;
    uint64_t size;
} code_cave_t;

int
code_cave_get(const Elf64_Ehdr header, const uint64_t ph_start, const uint64_t ph_end, code_cave_t *code_cave, int fd) {
    int off = lseek(fd, header.e_shoff, SEEK_SET);
    if (off != header.e_shoff) {
        perror("lseek - fd");
        return 1;
    }

    int bytes_read;

    Elf64_Shdr section_header;

    uint64_t last_section_end = ph_start;
    uint64_t next_section_start;

    uint64_t code_cave_biggest_start = 0;
    uint64_t code_cave_biggest_end = 0;

    for (int i = 0; i < header.e_shnum; i++) {
        bytes_read = read(fd, &section_header, sizeof(Elf64_Shdr));
        if (bytes_read != sizeof(Elf64_Shdr)) {
            perror("read");
            return 1;
        }

        const uint64_t sh_start = section_header.sh_offset;
        const uint64_t sh_end = section_header.sh_offset + section_header.sh_size;

        const uint16_t section_is_inside_program_header = sh_start >= ph_start && sh_end <= ph_end;
        if (section_is_inside_program_header) {
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

    next_section_start = ph_end;
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
program_header_get_next(const Elf64_Ehdr header, const Elf64_Phdr program_header_cur, Elf64_Phdr *program_header_next, int fd) {
    assert(program_header_next != NULL);

    int off = lseek(fd, header.e_phoff, SEEK_SET);
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
        write(STDOUT_FILENO, error, strlen(error));
        return 2;
    }

    *program_header_next = program_header_closest;
    return 0;
}

int
fd_set_to_ph_offset(int fd, const Elf64_Ehdr header, Elf64_Phdr program_header) {
    int off = lseek(fd, header.e_phoff, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_new");
        return 1;
    }

    Elf64_Phdr ph;

    for (int i = 0; i < header.e_phnum; i++) {
        int bytes_read = read(fd, &ph, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read");
            return 1;
        }

        if (program_header.p_vaddr == ph.p_vaddr) {
            off = lseek(fd, -sizeof(Elf64_Phdr), SEEK_CUR);
            if (off == -1) {
                perror("lseek - fd_new");
                return 1;
            }
            return 0;
        }
    }
    return 1;
}

void
print_payload(uint8_t *payload, size_t payload_size) {
    int i;
    for (i = 0; i < payload_size / 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            printf("0x%02x, ", payload[i * 8 + j]);
        }
        printf("\n");
    }
    size_t remainder = payload_size % 8;
    for (int j = 0; j < remainder; ++j) {
        printf("0x%02x, ", payload[i * 8 + j]);
    }
    printf("\n");
}

void
overwrite_entrypoint(uint8_t *payload, size_t payload_size, Elf64_Addr entrypoint, uint64_t marker) {
    for (int i = 0; i < payload_size - 8; ++i) {
        uint64_t *ptr = (uint64_t *)&payload[i];
        if (*ptr == marker) {
            *ptr = entrypoint;
            printf("Replaced stub marker with actual entrypoint\n");
            break;
        }
    }
}

int
shellcode_inject(Elf64_Ehdr header, Elf64_Phdr program_header, const code_cave_t code_cave, uint8_t shellcode[], const uint64_t shellcode_size, int fd,
                 size_t text_size) {

    overwrite_entrypoint(decryption_stub, sizeof(decryption_stub), header.e_entry, 0x4242424242424242);

    printf("Injecting payload:\n");
    print_payload(decryption_stub, sizeof(decryption_stub));
    printf("Old entrypoint: %lx\n", header.e_entry);

    // copy shellcode
    int off = lseek(fd, code_cave.start, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    int bytes_written = write(fd, decryption_stub, sizeof(decryption_stub));
    if (bytes_written != sizeof(decryption_stub)) {
        perror("write");
        return 1;
    }

    header.e_entry = program_header.p_vaddr + (code_cave.start - program_header.p_offset);

    off = lseek(fd, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    bytes_written = write(fd, &header, sizeof(Elf64_Ehdr));
    if (bytes_written != sizeof(Elf64_Ehdr)) {
        perror("write");
        return 1;
    }

    if (fd_set_to_ph_offset(fd, header, program_header)) return 1;

    program_header.p_filesz += sizeof(decryption_stub);
    program_header.p_memsz += sizeof(decryption_stub);
    write(fd, &program_header, sizeof(Elf64_Phdr));
    return 0;
}

int
main(int ac, char **av) {
    if (ac != 2) {
        printf("wrong usage: ./woody BINARY_NAME\n");
        return 1;
    }

    int file = open(av[1], O_RDONLY);
    if (file == -1) {
        perror(av[1]);
        return 1;
    }

    {
        int fd_new = open("woody", O_RDWR | O_CREAT | O_TRUNC, 0755);
        if (fd_new == -1) {
            perror("could not create new 'woody' binary:\n");
            return 1;
        }

        if (fd_copy_whole(fd_new, file)) return 1;

        file = fd_new;
    }

    int off = lseek(file, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_new");
        return 1;
    }

    Elf64_Ehdr header;
    int bytes_read = read(file, &header, sizeof(header));
    if (bytes_read != sizeof(header)) {
        perror("read");
        return 1;
    }

    if (elf64_ident_check(&header)) return 1;

    Elf64_Shdr section_header_entry;

    if (section_header_entry_get(header, &section_header_entry, file)) return 1;

    printf("sh offset 0x%lx\n", section_header_entry.sh_offset);

    Elf64_Phdr program_header_entry;
    if (program_header_by_section_header_get(header, section_header_entry, &program_header_entry, file)) return 1;

    printf("ph offset 0x%lx\n", program_header_entry.p_offset);

    Elf64_Phdr program_header_entry_next;
    if (program_header_get_next(header, program_header_entry, &program_header_entry_next, file)) return 1;

    printf("ph_next offset 0x%lx\n", program_header_entry_next.p_offset);

    code_cave_t code_cave;
    if (code_cave_get(header, program_header_entry.p_offset, program_header_entry_next.p_offset, &code_cave, file)) return 1;

    printf("codecave start 0x%lx\n", code_cave.start);
    printf("codecave size 0x%lx\n", code_cave.size);

    if (shellcode_inject(header, program_header_entry, code_cave, decryption_stub, sizeof(decryption_stub), file, section_header_entry.sh_size)) return 1;
    close(file);
}
