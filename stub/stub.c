#include <elf.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct {
    Elf64_Addr og_entry;
    size_t text_size;
    uint8_t key[16];
} __attribute__((packed)) WoodyData;

__attribute__((section(".text"))) WoodyData data = {
    .og_entry = 0xdeadbeefcafebabe,
    .text_size = 0x4242424242424242,
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

    XOR_decrypt((uint8_t *)data.og_entry, data.text_size, data.key);

    void (*entrypoint)() = (void (*)())data.og_entry;
    entrypoint();
}
