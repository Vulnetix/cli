#include <string.h>

unsigned char *entry_after(unsigned char *zm, size_t len)
{
    return zm + 1 + len;
}

char *tail_of(char *buf, size_t used)
{
    return &buf[used];
}

size_t key_length(const char *s)
{
    const char *p = strchr(s, '=');
    return p ? (size_t)(p - s) : strlen(s);
}
