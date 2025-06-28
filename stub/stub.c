#include <elf.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct {
    struct {
        Elf64_Addr entrypoint;
        size_t size;
    } text;
    uint8_t key[16];
} __attribute__((packed)) WoodyData;

__attribute__((section(".text"))) WoodyData data = {
    .text = {.entrypoint = 0xdeadbeefcafebabe, .size = 0x4242424242424242},
    .key = {0x42},
};

void
XOR_decrypt(uint8_t *restrict text, size_t text_size, uint8_t *restrict key) {
    for (size_t idx = 0; idx < text_size; ++idx) {
        text[idx] ^= key[idx % 16];
    }
}

void
_start() {
    const char msg[] = "....WOODY....\n";
    syscall(SYS_write, 1, msg, sizeof(msg) - 1);

    mprotect((void *)data.text.entrypoint, data.text.size, PROT_WRITE | PROT_READ);

    XOR_decrypt((uint8_t *)data.text.entrypoint, data.text.size, data.key);

    mprotect((void *)data.text.entrypoint, data.text.size, PROT_EXEC | PROT_READ);

    ((void (*)())data.text.entrypoint)();
}
