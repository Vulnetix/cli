#include <stdlib.h>

char *grow_keep_cursor(char *base, char *cur, size_t newcap)
{
    char *nb = realloc(base, newcap);
    if (nb == NULL)
        return NULL;
    size_t off = cur - base;
    return nb + off;
}
