#include <sys/syscall.h>
#include <unistd.h>

void
_start(void) {
    const char msg[] = "....WOODY....\n";
    syscall(SYS_write, 1, msg, sizeof(msg) - 1);

    syscall(SYS_exit, 42);
}
