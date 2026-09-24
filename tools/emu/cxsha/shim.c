// libc pieces for running the SDK's cx_sha256.c under Unicorn: memmove either
// byte by byte (like the simplest libc) or word by word when aligned.
#include <stddef.h>
#include <stdint.h>

void *memset(void *d, int c, size_t n) {
    unsigned char *p = d;
    while (n--) *p++ = (unsigned char) c;
    return d;
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *memmove(void *d, const void *s, size_t n) {
#ifdef WORD_MEMMOVE
    if ((((uintptr_t) d | (uintptr_t) s | n) & 3) == 0) {
        uint32_t *dd = d;
        const uint32_t *ss = s;
        size_t w = n / 4;
        if (dd < ss) { while (w--) *dd++ = *ss++; }
        else { while (w--) dd[w] = ss[w]; }
        return d;
    }
#endif
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd < ss) { while (n--) *dd++ = *ss++; }
    else { while (n--) dd[n] = ss[n]; }
    return d;
}

void explicit_bzero(void *d, size_t n) {
    memset(d, 0, n);
}

// The library's global scratch context (a union of all hash contexts), used by
// cx_hash_sha256. Size is ample for SHA-256.
__attribute__((aligned(8))) unsigned char G_cx[1024];
