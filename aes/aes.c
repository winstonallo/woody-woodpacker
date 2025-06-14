#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t SBoxArray[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
};
#define SBox(b) SBoxArray[(b & 0xF0) >> 4][b & 0x0F]

static const uint32_t Rcon[11] = {0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                                  0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

// val: uint32_t
#define RotWord(val) ((val << 8) | (val >> 24))
// val: uint32_t
#define SubWord(val) (uint32_t)((SBox(val & 0xFF)) | (SBox(((val >> 8) & 0xFF)) << 8) | (SBox(((val >> 16) & 0xFF)) << 16) | (SBox(((val >> 24) & 0xFF)) << 24))

__attribute__((always_inline)) static void
SubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = SBox(state[i]);
    }
}

__attribute__((always_inline)) static uint8_t
xTimes(uint8_t b) {
    if ((b & 0x80) == 0) {
        return b << 1;
    }

    return (b << 1) ^ 0b00011011; // x^4 + x^3 + x + 1
}

__attribute__((always_inline)) static uint8_t
xTimesx(uint8_t a, uint8_t x) {
    uint8_t res = 0;

    for (int i = 0; i < 8; ++i) {
        if (x & 1) {
            res ^= a;
        }
        x >>= 1;
        a = xTimes(a);
    }
    return res;
}

#define Mul02(b) xTimes(b)
#define Mul03(b) xTimes(b) ^ b

// Column-Major: s[row, col] = s[row + 4col]
__attribute__((always_inline)) static void
ShiftRows(uint8_t state[16]) {
    // Row 1: shift left by 1
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2 (swap pairs)
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: shift left by 3 (= shift right by 1)
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

__attribute__((always_inline)) static void
MixColumns(uint8_t state[16]) {
    uint8_t s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];
    state[0] = Mul02(s0) ^ Mul03(s1) ^ s2 ^ s3;
    state[1] = s0 ^ Mul02(s1) ^ Mul03(s2) ^ s3;
    state[2] = s0 ^ s1 ^ Mul02(s2) ^ Mul03(s3);
    state[3] = Mul03(s0) ^ s1 ^ s2 ^ Mul02(s3);

    uint8_t s4 = state[4], s5 = state[5], s6 = state[6], s7 = state[7];
    state[4] = Mul02(s4) ^ Mul03(s5) ^ s6 ^ s7;
    state[5] = s4 ^ Mul02(s5) ^ Mul03(s6) ^ s7;
    state[6] = s4 ^ s5 ^ Mul02(s6) ^ Mul03(s7);
    state[7] = Mul03(s4) ^ s5 ^ s6 ^ Mul02(s7);

    uint8_t s8 = state[8], s9 = state[9], s10 = state[10], s11 = state[11];
    state[8] = Mul02(s8) ^ Mul03(s9) ^ s10 ^ s11;
    state[9] = s8 ^ Mul02(s9) ^ Mul03(s10) ^ s11;
    state[10] = s8 ^ s9 ^ Mul02(s10) ^ Mul03(s11);
    state[11] = Mul03(s8) ^ s9 ^ s10 ^ Mul02(s11);

    uint8_t s12 = state[12], s13 = state[13], s14 = state[14], s15 = state[15];
    state[12] = Mul02(s12) ^ Mul03(s13) ^ s14 ^ s15;
    state[13] = s12 ^ Mul02(s13) ^ Mul03(s14) ^ s15;
    state[14] = s12 ^ s13 ^ Mul02(s14) ^ Mul03(s15);
    state[15] = Mul03(s12) ^ s13 ^ s14 ^ Mul02(s15);
}

__attribute__((always_inline)) static void
AddRoundKey(uint32_t *state, uint32_t *w) {
    state[0] ^= w[0];
    state[1] ^= w[1];
    state[2] ^= w[2];
    state[3] ^= w[3];
}

// Nr = 14 for AES-256
static uint8_t *
Cipher(uint8_t *in, uint8_t Nr, uint32_t *w) {
    uint8_t *state = malloc(16 * sizeof(uint8_t)); // TODO: put this on stack
    memcpy(state, in, 16);                         // TODO: use own memcpy/hardcode

    AddRoundKey((uint32_t *)state, w);

    for (int round = 1; round < Nr - 1; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey((uint32_t *)state, &w[4 * round]);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey((uint32_t *)state, &w[4 * Nr]);

    return state;
}

static uint32_t *
KeyExpansion(const uint32_t key[8]) {
    const uint8_t Nr = 14, Nk = 8;
    uint32_t *w = malloc((4 * (Nr + 1)) * sizeof(uint32_t)); // TODO: put this on stack
    for (int i = 0; i < Nk; ++i) {
        w[i] = key[i];
    }

    for (int i = Nk; i <= 4 * Nr + 3; ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
    return w;
}

#define TEST 1
#ifdef TEST
#include <assert.h>
int
main() {
    assert(xTimes(0x57) == 0xae);
    assert(xTimes(0xae) == 0x47);
    assert(xTimesx(0x57, 0x04) == 0x47);
    assert(xTimesx(0x57, 0x80) == 0x38);
    assert(SBox(0x53) == 0xed);
    assert(SubWord(0x53535353) == 0xedededed);

    uint8_t state[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    ShiftRows(state);
    assert(state[0] == 0);
    assert(state[4] == 4);
    assert(state[8] == 8);
    assert(state[12] == 12);
    assert(state[1] == 5);
    assert(state[5] == 9);
    assert(state[9] == 13);
    assert(state[13] == 1);
    assert(state[2] == 10);
    assert(state[6] == 14);
    assert(state[10] == 2);
    assert(state[14] == 6);
    assert(state[3] == 15);
    assert(state[7] == 3);
    assert(state[11] == 7);
    assert(state[15] == 11);

    assert(RotWord(0xaabbccdd) == 0xbbccddaa);

    const uint32_t input_key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
    uint32_t *w = KeyExpansion(input_key);

    uint32_t temp = 0x0914dff4;

    assert(w[0] == 0x603deb10);
    assert(w[1] == 0x15ca71be);
    assert(w[2] == 0x2b73aef0);
    assert(w[3] == 0x857d7781);
    assert(w[4] == 0x1f352c07);
    assert(w[5] == 0x3b6108d7);
    assert(w[6] == 0x2d9810a3);
    assert(w[7] == 0x0914dff4);
    assert(w[8] == 0x9ba35411);
    assert(w[9] == 0x8e6925af);
    assert(w[10] == 0xa51a8b5f);
    assert(w[11] == 0x2067fcde);
    assert(w[12] == 0xa8b09c1a);
    assert(w[13] == 0x93d194cd);
    assert(w[14] == 0xbe49846e);
    assert(w[15] == 0xb75d5b9a);
    assert(w[16] == 0xd59aecb8);
    assert(w[17] == 0x5bf3c917);
    assert(w[18] == 0xfee94248);
    assert(w[19] == 0xde8ebe96);
    assert(w[20] == 0xb5a9328a);
    assert(w[23] == 0x2f6c79b3);
    assert(w[24] == 0x812c81ad);
    assert(w[25] == 0xdadf48ba);
    assert(w[26] == 0x24360af2);
    assert(w[27] == 0xfab8b464);
    assert(w[28] == 0x98c5bfc9);
    assert(w[29] == 0xbebd198e);
    assert(w[30] == 0x268c3ba7);
    assert(w[31] == 0x09e04214);
    assert(w[32] == 0x68007bac);
    assert(w[33] == 0xb2df3316);
    assert(w[34] == 0x96e939e4);
    assert(w[35] == 0x6c518d80);
    assert(w[36] == 0xc814e204);
    assert(w[37] == 0x76a9fb8a);
    assert(w[38] == 0x5025c02d);
    assert(w[39] == 0x59c58239);
    assert(w[40] == 0xde136967);
    assert(w[41] == 0x6ccc5a71);
    assert(w[42] == 0xfa256395);
    assert(w[43] == 0x9674ee15);
    assert(w[44] == 0x5886ca5d);
    assert(w[45] == 0x2e2f31d7);
    assert(w[46] == 0x7e0af1fa);
    assert(w[47] == 0x27cf73c3);
    assert(w[48] == 0x749c47ab);
    assert(w[49] == 0x18501dda);
    assert(w[50] == 0xe2757e4f);
    assert(w[51] == 0x7401905a);
    assert(w[52] == 0xcafaaae3);
    assert(w[53] == 0xe4d59b34);
    assert(w[54] == 0x9adf6ace);
    assert(w[55] == 0xbd10190d);
    assert(w[56] == 0xfe4890d1);
    assert(w[57] == 0xe6188d0b);
    assert(w[58] == 0x046df344);
    assert(w[59] == 0x706c631e);
    free((void *)w);
}
#endif
