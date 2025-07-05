#include <elf.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int
fd_copy_whole(int fd_dest, int fd_src) {

    int bytes_read;
    int bytes_written;

    int off = lseek(fd_src, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_src");
        return 1;
    }

    char buf[100];
    do {
        bytes_read = read(fd_src, &buf, sizeof(buf));
        if (bytes_read == -1) {
            perror("read - fd_src");
            return 1;
        }
        bytes_written = write(fd_dest, &buf, bytes_read);
        if (bytes_written == -1) {
            perror("write - fd_dest");
            return 1;
        }
    } while (bytes_read == sizeof(buf));

    return 0;
}

int
file_duplicate(char **av) {
    int file = open(av[1], O_RDONLY);
    if (file == -1) {
        perror(av[1]);
        return -1;
    }

    int fd_new = open("woody", O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd_new == -1) {
        perror("could not create new 'woody' binary:\n");
        return -1;
    }

    if (fd_copy_whole(fd_new, file)) return -1;

    return fd_new;
}

int
fd_set_to_ph_offset(int fd, const Elf64_Ehdr header, Elf64_Phdr program_header) {
    int off = lseek(fd, header.e_phoff, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_new");
        return 1;
    }

    Elf64_Phdr ph;

    for (int i = 0; i < header.e_phnum; i++) {
        int bytes_read = read(fd, &ph, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read");
            return 1;
        }

        if (program_header.p_vaddr == ph.p_vaddr) {
            off = lseek(fd, -sizeof(Elf64_Phdr), SEEK_CUR);
            if (off == -1) {
                perror("lseek - fd_new");
                return 1;
            }
            return 0;
        }
    }
    return 1;
}
