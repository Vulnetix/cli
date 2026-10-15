#include <string.h>
#include <stdlib.h>

size_t prefix_len(const char *s)
{
    const char *comma = strchr(s, ',');
    if (!comma)
        return strlen(s);
    return (size_t)(comma - s);
}

size_t used(void)
{
    char *buf = malloc(128);
    char *cur = buf + 10;
    size_t n = cur - buf;
    free(buf);
    return n;
}
