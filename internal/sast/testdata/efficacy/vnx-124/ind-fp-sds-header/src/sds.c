#include <stdlib.h>

typedef char *sds;

void sds_set_type(sds s, unsigned char type)
{
    s[-1] = type;
}

int ends_with_newline(const char *s, size_t n)
{
    return n > 0 && s[n - 1] == '\n';
}
