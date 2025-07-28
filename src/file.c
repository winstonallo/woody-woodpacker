#include "woody.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int
file_munmap(const File file) {
    return munmap(file.mem, file.size);
}

int
file_mmap(const char *file_name, File *file) {
    assert(file_name != NULL);
    assert(file != NULL);

    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "(open) Error on %s: %s\n", file_name, strerror(errno));
        return 1;
    }

    int off = lseek(fd, 0, SEEK_END);
    if (off == -1) {
        if (errno != 0) {
            perror(file_name);
        } else {
            fprintf(stderr, "(lseek) Error on fd %d. You likely passed a directory as a file - we cannot use fcntl, so all we can do is guess\n", fd);
        }
        close(fd);
        return 1;
    }
    file->size = off;

    off = lseek(fd, 0, SEEK_SET);
    if (off != 0) {
        close(fd);
        perror(file_name);
        return 1;
    }

    file->mem = mmap(NULL, file->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (file->mem == MAP_FAILED) {
        fprintf(stderr, "(mmap) Error mapping %s: %s\n", file_name, strerror(errno));
        return 1;
    }

    return 0;
}

int
file_write(File file) {
    const char *outfile = "woody";
    int fd = open(outfile, O_CREAT | O_RDWR, 0755);
    if (fd == -1) {
        fprintf(stderr, "(open) Error on %s: %s\n", outfile, strerror(errno));
        return 1;
    }
    size_t bytes_written = write(fd, file.mem, file.size);
    if (bytes_written != file.size) {
        close(fd);
        fprintf(stderr, "(open) Error on %s (fd %d): %s\n", outfile, fd, strerror(errno));
        return 1;
    }

    close(fd);
    return 0;
}
