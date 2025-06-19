#include "../aes/aes.c"
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
    uint64_t og_entry;
    uint64_t enc_text_addr;
    uint64_t enc_text_size;
    uint8_t aes256_key[32];
} __attribute__((packed)) WoodyData;

void
_start() {
    const char msg[] = "....WOODY....\n";
    write(1, msg, sizeof(msg));

    uint64_t woody_data_addr = 0x4242424242424242ULL;
    WoodyData *data = (WoodyData *)woody_data_addr;

    uint32_t key[60];
    KeyExpansion(data->aes256_key, key);

    uint8_t *enc_text = (uint8_t *)data->enc_text_addr;

    uintptr_t page_start = ((uintptr_t)enc_text) & ~0xFFF;
    size_t page_size = (data->enc_text_size + 0xFFF) & ~0xFFF;
    mprotect((void *)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    for (uint64_t block = 0; block < data->enc_text_size; block += 16) {
        uint8_t in[16] = {0};
        uint8_t out[16];

        size_t block_size = (block + 16 <= data->enc_text_size) ? 16 : data->enc_text_size - block;

        for (size_t block_idx = 0; block_idx < block_size; ++block_idx) {
            in[block_idx] = enc_text[block + block_idx];
        }

        InvCipher(in, out, key);

        for (size_t block_idx = 0; block_idx < block_size; ++block_idx) {
            enc_text[block + block_idx] = out[block_idx];
        }
    }

    void (*og_main)(void) = (void (*)(void))data->og_entry;
    og_main();
}
