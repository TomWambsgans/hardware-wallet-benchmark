// What the crypto sources need from libc, for the freestanding emulator build.
#include <stddef.h>

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n--) {
        *dd++ = *ss++;
    }
    return d;
}

void *memset(void *d, int c, size_t n) {
    unsigned char *dd = d;
    while (n--) {
        *dd++ = (unsigned char) c;
    }
    return d;
}
