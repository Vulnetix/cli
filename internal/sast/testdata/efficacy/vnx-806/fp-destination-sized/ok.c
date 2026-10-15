#include <string.h>

void ok(const char *src, const unsigned char *raw) {
    char dst[32];
    uint64_t x;
    unsigned char buf[16];
    long val = 5;
    memcpy(dst, src, sizeof(dst));
    memcpy(&x, raw, sizeof(x));
    memcpy(buf, &val, sizeof(val));
    memcpy(dst, "literal", strlen("literal"));
    strncpy(dst, src, sizeof(dst) - 1);
    /* memcpy(dst, src, strlen(src)); is the bug this avoids */
}
