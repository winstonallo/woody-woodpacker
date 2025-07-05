#include "inc/utils.h"
#include "inc/woody.h"
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int
key_create(int ac, char **av, u_int8_t *key) {
    if (ac == 2) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1) {
            perror("Could not generate random XOR key");
            return 1;
        }
        if (read(fd, key, 16) == -1) {
            perror("Could not generate random XOR key");
            close(fd);
            return 1;
        }
        close(fd);
    } else {
        if (ft_strlen(av[3]) != 32) {
            fprintf(stderr, "Invalid key length - must be 16 hex bytes (32 characters)");
            return 1;
        } else if (parsehex((const uint8_t *)av[3], key) == -1) {
            fprintf(stderr, "Invalid input - only lowercase hexadecimal supported");
            return 1;
        }
    }
    return 0;
}

int
section_text_encrypt(const Elf64_Shdr section_header_entry, int fd, const uint8_t key[16]) {

    size_t off = lseek(fd, section_header_entry.sh_offset, SEEK_SET);
    if (off != section_header_entry.sh_offset) {
        perror("lseek");
        return 1;
    }

    uint8_t enc;
    for (size_t i = 0; i < section_header_entry.sh_size; i++) {
        int bytes_read = read(fd, &enc, 1);
        if (bytes_read != 1) {
            perror("read");
            return 1;
        }

        enc ^= key[i % 16];

        int off = lseek(fd, -1, SEEK_CUR);
        if (off == -1) {
            perror("lseek");
            return 1;
        }

        int bytes_written = write(fd, &enc, 1);
        if (bytes_written != 1) {
            perror("read");
            return 1;
        }
    }
    return 0;
}
