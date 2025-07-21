#include "inc/woody.h"
#include <assert.h>
#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

const Elf64_Shdr *
section_header_entry_get(file file, const Elf64_Ehdr header) {
    assert(file.mem != NULL);
    assert(header.e_shoff + header.e_shnum * header.e_shentsize <= file.size);

    const Elf64_Shdr *section_header_table = file.mem + header.e_shoff;

    for (int i = 0; i < header.e_shnum; i++) {
        const Elf64_Shdr *sh = section_header_table + i;
        if (sh->sh_addr <= header.e_entry && (sh->sh_addr + sh->sh_size) > header.e_entry) {
            return sh;
        }
    }

    fprintf(stderr, "error: could not find section header that is pointed to by e_entry\n");
    return NULL;
}
