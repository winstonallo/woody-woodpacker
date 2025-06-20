#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    struct {
        uint8_t *data;
        size_t len;
    } msg;
    uint8_t *key;
} Aes256Data;

Aes256Data *Aes256_ECB_Encrypt(Aes256Data *);
Aes256Data *Aes256_ECB_Decrypt(Aes256Data *);

#endif
