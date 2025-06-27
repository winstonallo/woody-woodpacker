#include <elf.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct {
    Elf64_Addr og_entry;
} __attribute__((packed)) WoodyData;

void
_start(void) {
    WoodyData woody_data = {.og_entry = 0xdeadbeefcafebabeULL};

    const char msg[] = "....WOODY....\n";
    syscall(SYS_write, 1, msg, sizeof(msg) - 1);

    syscall(SYS_exit, 42);
}
