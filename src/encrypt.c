#include "str.h"
#include "woody.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int
parse_or_generate_key(int ac, char **av, u_int8_t *key) {
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
        if (ft_strlen(av[2]) != 32) {
            fprintf(stderr, "Invalid key length - must be 16 hex bytes (32 characters)\n");
            return 1;
        } else if (parsehex((const uint8_t *)av[2], key) == -1) {
            fprintf(stderr, "Invalid key - only lowercase hexadecimal supported\n");
            return 1;
        }
    }
    return 0;
}

void
encrypt(File file, const Elf64_Shdr shdr, const uint8_t key[16]) {
    assert(file.mem != NULL);

    const uint64_t start = shdr.sh_offset;
    const uint64_t size = shdr.sh_size;

    assert(file.size >= start + size);

    for (size_t i = 0; i < size; i++) {
        uint8_t *enc = file.mem + start + i;
        *enc ^= key[i % 16];
    }
}
