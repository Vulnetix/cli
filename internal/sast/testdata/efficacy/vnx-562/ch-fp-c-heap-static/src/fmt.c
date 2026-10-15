#include <stdlib.h>
#include <string.h>

char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    memcpy(out, s, n);
    return out;
}

const char *version(void)
{
    static char buf[32];
    strcpy(buf, "1.0");
    return buf;
}
