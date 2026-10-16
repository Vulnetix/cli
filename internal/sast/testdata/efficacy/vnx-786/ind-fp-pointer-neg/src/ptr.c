#include <stddef.h>

int prev_char(const char *base, size_t off)
{
    const char *p = base + off;
    // negative index on a pointer into the middle of a buffer is fine
    return p[-1];
}

/* line[strlen(line) - 1] = 0; in a comment */
const char *doc = "buf[strlen(buf) - 1] = 0";
