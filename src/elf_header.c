#include "woody.h"
#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <unistd.h>

static const char *error_messages[] = {
    "", "Invalid EI_MAG field in header", "Not 64-bit", "Invalid data encoding in header", "Invalid version in header", "Invalid padding in header"};

const char *
elf64_ident_check(const Elf64_Ehdr *h) {
    assert(h != NULL);

    if (h->e_ident[EI_MAG0] != ELFMAG0 || h->e_ident[EI_MAG1] != ELFMAG1 || h->e_ident[EI_MAG2] != ELFMAG2 || h->e_ident[EI_MAG3] != ELFMAG3) {
        return error_messages[INVALID_EI_MAG];
    }

    if (h->e_ident[EI_CLASS] != ELFCLASS64) return error_messages[NOT_64_BIT];

    if (h->e_ident[EI_DATA] == ELFDATANONE) return error_messages[NO_DATA];

    if (h->e_ident[EI_VERSION] != EV_CURRENT) return error_messages[INVALID_VERSION];

    for (size_t i = EI_PAD; i < sizeof(h->e_ident); i++) {
        if (h->e_ident[i] != 0) return error_messages[INVALID_PADDING];
    }
    return error_messages[SUCCESS];
}
