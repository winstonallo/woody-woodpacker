#ifndef UTILS_H
#define UTILS_H

#include <elf.h>
#include <stddef.h>

void *ft_memcpy(void *dst, const void *src, size_t n);
int put_str(int fd, char *str);
int ft_strlen(char *str);
int fd_set_to_ph_offset(int fd, const Elf64_Ehdr header, Elf64_Phdr program_header);
int parsehex(const uint8_t *restrict bytes, uint8_t *const restrict out);

#endif
