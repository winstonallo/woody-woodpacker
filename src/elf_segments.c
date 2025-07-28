#include "woody.h"
#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <unistd.h>

Elf64_Phdr *
phdr_get_by_shdr(File file, const Elf64_Ehdr header, const Elf64_Shdr shdr) {
    assert(file.mem != NULL);
    assert(header.e_phoff + header.e_phnum * header.e_phentsize <= file.size);

    const uint64_t sh_start = shdr.sh_offset;
    const uint64_t sh_end = shdr.sh_offset + shdr.sh_size - 1;

    Elf64_Phdr *phdr_table = file.mem + header.e_phoff;

    for (int i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr *ph = phdr_table + i;

        const uint64_t ph_start = ph->p_offset;
        const uint64_t ph_end = ph->p_offset + ph->p_filesz;

        const uint16_t section_is_inside_phdr = sh_start >= ph_start && sh_end <= ph_end;
        if (section_is_inside_phdr) {
            return ph;
        }
    }

    fprintf(stderr, "could not find program header with section header inside\n");
    return NULL;
}

const Elf64_Phdr *
phdr_get_next(File file, const Elf64_Ehdr header, const Elf64_Phdr phdr) {
    assert(file.mem != NULL);
    assert(header.e_phoff + header.e_phnum * header.e_phentsize <= file.size);

    Elf64_Phdr *phdr_table = file.mem + header.e_phoff;

    Elf64_Phdr *phdr_closest = NULL;

    for (int i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr *ph = phdr_table + i;
        if (phdr.p_offset < ph->p_offset) {
            if (phdr_closest == NULL) {
                phdr_closest = ph;
                continue;
            }

            const uint64_t distance_cur = ph->p_offset - phdr.p_offset;
            const uint64_t distance_old = ph->p_offset - phdr_closest->p_offset;
            if (distance_cur < distance_old) phdr_closest = ph;
        }
    }

    if (phdr_closest == NULL) {
        fprintf(stderr, "could not find program header after current one\n");
        return NULL;
    }

    return phdr_closest;
}
