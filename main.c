#include "stub_bytes.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
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
section_header_entry_get(Elf64_Ehdr *header, Elf64_Shdr *section_header_entry, int fd) {
    assert(header != NULL);
    assert(section_header_entry != NULL);

    int bytes_read;
    Elf64_Shdr section_header;

    int off = lseek(fd, header->e_shoff, SEEK_SET);
    if (off != header->e_shoff) {
        perror("lseek - section_header_entry_get fd");
        return 1;
    }

    for (int i = 0; i < header->e_shnum; i++) {
        bytes_read = read(fd, &section_header, sizeof(Elf64_Shdr));
        if (bytes_read != sizeof(Elf64_Shdr)) {
            perror("read");
            return 1;
        }

        if (section_header.sh_addr == header->e_entry) {
            *section_header_entry = section_header;
            return 0;
        }
    }

    char *error = "could not find section header that is pointed to by e_entry";
    write(STDOUT_FILENO, error, strlen(error));
    return 2;
}

int
program_header_by_section_header_get(Elf64_Ehdr *header, Elf64_Shdr *section_header, Elf64_Phdr *program_header_res, int fd) {
    assert(header != NULL);
    assert(section_header != NULL);
    assert(program_header_res != NULL);

    int off = lseek(fd, header->e_phoff, SEEK_SET);
    if (off != header->e_phoff) {
        perror("lseek - fd");
        return 1;
    }

    const uint64_t sh_start = section_header->sh_offset;
    const uint64_t sh_end = section_header->sh_offset + section_header->sh_size;

    int bytes_read;
    Elf64_Phdr program_header;

    for (int i = 0; i < header->e_phnum; i++) {
        bytes_read = read(fd, &program_header, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read");
            return 1;
        }

        const uint64_t ph_start = program_header.p_offset;
        const uint64_t ph_end = program_header.p_offset + program_header.p_filesz;

        const uint16_t section_is_inside_program_header = sh_start >= ph_start && sh_end <= ph_end;
        if (section_is_inside_program_header) {
            *program_header_res = program_header;
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
make_jump_code(uint8_t *buffer, void *target) {
    buffer[0] = 0x48; // REX.W prefix for 64-bit operand
    buffer[1] = 0xB8; // MOV RAX, imm64
    // Copy the 8-byte address into the next bytes
    memcpy(&buffer[2], &target, 8);
    buffer[10] = 0xFF; // JMP RAX
    buffer[11] = 0xE0;
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

    if (section_header_entry_get(&header, &section_header_entry, file)) return 1;

    printf("sh offset 0x%lx\n", section_header_entry.sh_offset);

    Elf64_Phdr program_header_entry;
    if (program_header_by_section_header_get(&header, &section_header_entry, &program_header_entry, file)) return 1;

    printf("ph offset 0x%lx\n", program_header_entry.p_offset);

    Elf64_Phdr program_header_entry_next;
    if (program_header_get_next(header, program_header_entry, &program_header_entry_next, file)) return 1;

    printf("ph_next offset 0x%lx\n", program_header_entry_next.p_offset);

    code_cave_t code_cave;
    if (code_cave_get(header, program_header_entry.p_offset, program_header_entry_next.p_offset, &code_cave, file)) return 1;

    printf("codecave start 0x%lx\n", code_cave.start);
    printf("codecave size 0x%lx\n", code_cave.size);

    // unsigned char shellcode[] = {
    //     0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    //     0xBB, 0x2A, 0x00, 0x00, 0x00, // mov ebx, 42
    //     0xCD, 0x80                    // int 0x80
    // };

    uint8_t shellcode[12];
    make_jump_code(shellcode, (void *)header.e_entry);

    // copy shellcode
    off = lseek(file, code_cave.start, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    int bytes_written = write(file, shellcode, sizeof(shellcode));
    if (bytes_written != sizeof(shellcode)) {
        perror("write");
        return 1;
    }

    header.e_entry = program_header_entry.p_vaddr + (code_cave.start - program_header_entry.p_offset);

    off = lseek(file, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek");
        return 1;
    }

    bytes_written = write(file, &header, sizeof(Elf64_Ehdr));
    if (bytes_written != sizeof(Elf64_Ehdr)) {
        perror("write");
        return 1;
    }

    if (fd_set_to_ph_offset(file, header, program_header_entry)) return 1;

    program_header_entry.p_filesz += sizeof(shellcode);
    program_header_entry.p_memsz += sizeof(shellcode);
    write(file, &program_header_entry, sizeof(Elf64_Phdr));

    close(file);
    // // Find .text section header
    // Elf64_Shdr *section_header_text;

    // for (int i = 0; i < header->e_shnum; i++) {
    //     section_header_text = (Elf64_Shdr *)&binary.data[header->e_shoff + (i * sizeof(Elf64_Shdr))];

    //     if (section_header_text->sh_addr == header->e_entry) break;
    // }

    // Elf64_Phdr *program_header;
    // for (int i = 0; i < header->e_phnum; i++) {
    //     program_header = (Elf64_Phdr *)&binary.data[header->e_phoff + (i * sizeof(Elf64_Phdr))];

    //     uint64_t start = program_header->p_vaddr;
    //     uint64_t end = program_header->p_vaddr + program_header->p_filesz;

    //     if (start <= header->e_entry && end > header->e_entry) break;
    //     program_header = 0;
    // }

    // if (program_header == 0) {
    //     printf("can't find dont'want to write error message");
    //     return 1;
    // }

    // int f = 0;

    // uint64_t next_section_start = 0;
    // uint64_t last_section_end = program_header->p_offset;

    // uint64_t code_cave_biggest_start = 0;
    // uint64_t code_cave_biggest_end = 0;
    // for (int i = 0; i < header->e_shnum; i++) {
    //     Elf64_Shdr *section_header;
    //     section_header = (Elf64_Shdr *)&binary.data[header->e_shoff + (i * sizeof(Elf64_Shdr))];

    //     uint64_t start = program_header->p_offset;
    //     uint64_t end = program_header->p_offset + program_header->p_filesz;
    //     if (f == 1) {
    //         next_section_start = section_header->sh_offset;
    //         uint64_t code_cave_size = code_cave_biggest_end - code_cave_biggest_start;
    //         if (code_cave_size < next_section_start - last_section_end) {
    //             code_cave_biggest_start = last_section_end;
    //             code_cave_biggest_end = next_section_start;
    //         }

    //         last_section_end = section_header->sh_offset + section_header->sh_size;
    //         f = 0;
    //     } else if (section_header->sh_offset >= start && (section_header->sh_offset + section_header->sh_size) <= end) {
    //         f = 1;
    //         next_section_start = section_header->sh_offset;
    //         uint64_t code_cave_size = code_cave_biggest_end - code_cave_biggest_start;
    //         if (code_cave_size < next_section_start - last_section_end) {
    //             code_cave_biggest_start = last_section_end;
    //             code_cave_biggest_end = next_section_start;
    //         }

    //         last_section_end = section_header->sh_offset + section_header->sh_size;
    //     }
    // }

    // printf("Start %lx\n", code_cave_biggest_start);
    // printf("End %lx\n", code_cave_biggest_end);

    // // Find the code cave between .text and the next section

    // program_header->p_filesz = 0x1000;

    // uint64_t shellcode_offset = code_cave_biggest_start + code_cave_biggest_start % 8;
    // printf("shellcode offset: %lx\n", shellcode_offset);

    // memcpy(binary.data + shellcode_offset, decryption_stub, sizeof(decryption_stub));

    // uint64_t shellcode_addr = section_header_text->sh_addr + (shellcode_offset - section_header_text->sh_offset);

    // printf("text start  0x%lx\n", section_header_text->sh_addr);
    // printf("stub addr   0x%lx\n", section_header_text->sh_addr + section_header_text->sh_size);

    // // section_header_text->sh_size += sizeof(decryption_stub);
    // header->e_entry = shellcode_addr;
    // printf("shellcode vaddr %lx\n", shellcode_addr);

    // int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    // if (fd == -1) {
    //     perror("could not create new 'woody' binary:");
    //     return -1;
    // }

    // write(fd, binary.data, binary.len);

    // // for (int i = 0; i < section_header.sh_size; i++)
    // // {
    // //     char c;
    // //     read(file, &c, 1);
    // //     if (c == '7')
    // //     {
    // //         printf("(%i|%c)\n", i, c);
    // //         lseek(file, -1, SEEK_CUR);
    // //         write(file, "*", 1);
    // //     }
    // // }
    // // printf("\n");

    // // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // // for (int i = 0; i < section_header.sh_size; i++)
    // // {
    // //     char c;
    // //     c = '*';
    // //     write(file, &c, 1);
    // //     // read(file, &c, 1);
    // //     // if (c == '7')
    // //     // {
    // //     //     lseek(file, -1, SEEK_CUR);
    // //     //     write(file, "8", 1);
    // //     //     printf("Changed\n");
    // //     // }
    // // }
    // // printf("----------------\n");

    // // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // // for (int i = 0; i < section_header.sh_size; i++)
    // // {
    // //     char c;
    // //     read(file, &c, 1);
    // //     printf("%c", c);
    // // }
    // // printf("\n");
    // // fflush(file);
    // free(binary.data);
    // return 0;
    // // Read an elf binary
    // // Check if its a 64 bit elf with the starting values

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
