#include <assert.h>
#include <elf.h>
#include <stdio.h>
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

    for (size_t i = EI_PAD; i < sizeof(header->e_ident); i++) {
        if (header->e_ident[i] != 0) return 5;
    }
    return 0;
}

int
elf_header_parse(int fd, Elf64_Ehdr *header) {
    int off = lseek(fd, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_new");
        return 1;
    }

    int bytes_read = read(fd, header, sizeof(Elf64_Ehdr));
    if (bytes_read != sizeof(Elf64_Ehdr)) {
        perror("read");
        return 1;
    }

    if (elf64_ident_check(header)) return 1;

    return 0;
}
