#include "inc/utils.h"
#include <assert.h>
#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

int
section_header_entry_get(const Elf64_Ehdr header, Elf64_Shdr *section_header_entry, int fd) {
    assert(section_header_entry != NULL);

    size_t off = lseek(fd, header.e_shoff, SEEK_SET);
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

        if (sh.sh_addr <= header.e_entry && (sh.sh_addr + sh.sh_size) > header.e_entry) {
            *section_header_entry = sh;
            return 0;
        }
    }

    put_str(STDERR_FILENO, "could not find section header that is pointed to by e_entry\n");
    return 2;
}
