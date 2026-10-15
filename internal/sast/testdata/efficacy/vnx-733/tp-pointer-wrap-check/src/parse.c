#include <stddef.h>

int read_field(const char *buf, size_t len, size_t off) {
    const char *end = buf + len;
~>    if (buf + off < buf)
        return -1;
    return end[-1];
}

int copy_chunk(unsigned char *p, size_t n, unsigned char *limit) {
~>    if (p + n <= p || p + n > limit) {
        return -1;
    }
    return 0;
}
