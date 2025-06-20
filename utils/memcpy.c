#include <stddef.h>

// Performs block copy with `movsb` on x86-84, falls back to naive memcpy
// on other architectures.
//
// `dst` and `src` MAY overlap.
void *
ft_memcpy(void *dest, const void *src, size_t n) {
#ifdef __x86_64__
    __asm__ volatile("mov %0, %%rsi;"
                     "mov %1, %%rdi;"
                     "cld;"
                     "rep movsb"
                     : "+a"(src), "+d"(dest)
                     : "c"(n)
                     : "memory", "flags", "rsi", "rdi");
#else
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    if (!dest || !src || n == 0) {
        return dest;
    }

    if (d < s || d >= s + n) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }

#endif
    return (dest);
}
