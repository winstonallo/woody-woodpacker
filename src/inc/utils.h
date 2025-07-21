#ifndef UTILS_H
#define UTILS_H

#include <elf.h>
#include <stddef.h>

int fd_set_to_ph_offset(int fd, const Elf64_Ehdr header, Elf64_Phdr program_header);
int parsehex(const uint8_t *restrict bytes, uint8_t *const restrict out);

#endif
