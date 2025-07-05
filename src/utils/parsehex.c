#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

// Parses 16 hex bytes (32 characters) into a 16 bytes array (`out`).
//
// This function expects `bytes` 's length to be exactly 32 (16 hex bytes).
// Anything longer will be truncated, and anything shorter will result in
// invalid memory access.
//
// `bytes` and `out` may not overlap.
int
parsehex(const uint8_t *restrict bytes, uint8_t *const restrict out) {
    for (int i = 0; i < 32; ++i) {
        int hi = 0, lo = 0;
        if (isdigit(bytes[i * 2])) {
            hi = bytes[i * 2] - '0';
        } else if (bytes[i * 2] >= 'a' && bytes[i * 2] <= 'f') {
            hi = bytes[i * 2] - ('a' - 10);
        } else {
            return -1;
        }
        if (isdigit(bytes[i * 2 + 1])) {
            lo = bytes[i * 2 + 1] - '0';
        } else if (bytes[i * 2 + 1] >= 'a' && bytes[i * 2 + 1] <= 'f') {
            lo = bytes[i * 2 + 1] - ('a' - 10);
        } else {
            return -1;
        }
        out[i] = (hi * 16) + lo;
    }
    return 0;
}
