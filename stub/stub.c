#include <elf.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

// typedef struct {
//     Elf64_Addr og_entry;
//     size_t text_size;
//     uint8_t key[1];
// } __attribute__((packed)) WoodyData;

// __attribute__((section(".text"))) WoodyData data = {
//     .og_entry = 0xdeadbeefcafebabe,
//     .text_size = 0x4242424242424242,
//     .key = {0xff},
// };

void
_start() {
    syscall(SYS_exit, 42);
}
// void
// XOR_decrypt(uint8_t *restrict text, size_t text_size, uint8_t *restrict key) {
//     for (size_t idx = 0; idx < text_size; ++idx) {
//         text[idx] ^= key[idx % 1];
//     }
// }

