#include <string.h>

void fill(const char *src)
{
    char buf[64];
    char *end = buf + sizeof(buf);
    char *last = &buf[sizeof(buf)];
    strncpy(buf, src, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    (void)end;
    (void)last;
}

void bytes(unsigned char *raw)
{
    unsigned char *after = raw + sizeof(unsigned int);
    (void)after;
}
