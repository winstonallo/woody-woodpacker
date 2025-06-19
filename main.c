#include <sys/mman.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20 // cant find MAP_ANONYMOUS in sys/mman.h when running on Macs
#endif

void *alloc(size_t size);

int elf64_ident_check(const Elf64_Ehdr *header);

int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("wrong usage: ./woody BINARY_NAME\n");
        return 1;
    }

    Elf64_Ehdr header;
    int file = open(av[1], O_RDWR);

    int bytes_read = read(file, &header, sizeof(header));
    if (bytes_read != sizeof(header))
    {
        printf("error while reading %i bytes read from %i\n", bytes_read, sizeof(header));
        return 1;
    }

    int err = elf64_ident_check(&header);
    if (err)
    {
        printf("error while checking ident of elf with code: %i\n", err);
        return 1;
    }

    // printf("%i\n", header.e_type);
    // printf("%i\n", header.e_machine);
    // printf("%i\n", header.e_version);
    // printf("0x%x\n", header.e_entry);
    // printf("%i\n", header.e_ehsize);

    // printf("%x\n", header.e_entry);

    // Secions
    printf("Sections\n");

    printf("Offset %i\n", header.e_shoff);
    printf("Number %i\n", header.e_shnum);

    printf("Size of each entry %i\n", header.e_shentsize);

    int offset = lseek(file, header.e_shoff, SEEK_SET);
    if (offset != header.e_shoff)
    {
        printf("error while offsetting fd\n");
        return 1;
    }

    Elf64_Shdr section_header = {0};

    for (int i = 0; i < header.e_shnum; i++)
    {
        bytes_read = read(file, &section_header, sizeof(section_header));
        if (bytes_read != sizeof(section_header))
        {
            printf("error while reading %i bytes read from %i\n", bytes_read, sizeof(header));
            return 1;
        }

        if (section_header.sh_addr == header.e_entry)
            break;

        // printf("%x\n", section_header.sh_addr);
        // printf("%x\n", section_header.sh_offset);
        // printf("----------\n");
    }

    printf("%x\n", section_header.sh_size);

    offset = lseek(file, section_header.sh_offset, SEEK_SET);
    if (offset != section_header.sh_offset)
    {
        printf("error while offsetting fd\n");
        return 1;
    }

    unsigned char exit_code_4_shellcode[] = {
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
        0x48, 0xc7, 0xc7, 0x04, 0x00, 0x00, 0x00, // mov rdi, 4
        0x0f, 0x05                                // syscall
    };

    write(file, exit_code_4_shellcode, sizeof(exit_code_4_shellcode));

    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     read(file, &c, 1);
    //     if (c == '7')
    //     {
    //         printf("(%i|%c)\n", i, c);
    //         lseek(file, -1, SEEK_CUR);
    //         write(file, "*", 1);
    //     }
    // }
    // printf("\n");

    // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     c = '*';
    //     write(file, &c, 1);
    //     // read(file, &c, 1);
    //     // if (c == '7')
    //     // {
    //     //     lseek(file, -1, SEEK_CUR);
    //     //     write(file, "8", 1);
    //     //     printf("Changed\n");
    //     // }
    // }
    // printf("----------------\n");

    // offset = lseek(file, section_header.sh_offset, SEEK_SET);
    // for (int i = 0; i < section_header.sh_size; i++)
    // {
    //     char c;
    //     read(file, &c, 1);
    //     printf("%c", c);
    // }
    // printf("\n");
    // fflush(file);
    return 0;
    // Read an elf binary
    // Check if its a 64 bit elf with the starting values

    // Where does the execution start

    // Read the whole code segment
    // Apply encryption
    // save it to file
    //

    // Add a code segment to elf which decrypts the code segment
    // printf("%p\n", &main);
    // __uint64_t add = &alloc;
    // printf("%p\n", add);
    // add = add - (add % 4096);
    // printf("%p\n", add);
    // int a = mprotect(add, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    // if (a)
    //     return a;
    // int *p = alloc(1);
}

int elf64_ident_check(const Elf64_Ehdr *header)
{
    assert(header);

    if (header->e_ident[EI_MAG0] != ELFMAG0)
        return 1;
    if (header->e_ident[EI_MAG1] != ELFMAG1)
        return 1;
    if (header->e_ident[EI_MAG2] != ELFMAG2)
        return 1;
    if (header->e_ident[EI_MAG3] != ELFMAG3)
        return 1;

    if (header->e_ident[EI_CLASS] != ELFCLASS64)
        return 2;

    if (header->e_ident[EI_DATA] == ELFDATANONE)
        return 3;

    if (header->e_ident[EI_VERSION] != EV_CURRENT)
        return 4;

    for (int i = EI_PAD; i < sizeof(*header); i++) {
        if (header->e_ident[i] != 0) return 5;
    }
    return 0;
}