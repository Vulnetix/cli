#include <stdlib.h>
#include <string.h>

int count_commas(const char *src)
{
    char *buf = strdup(src);
    char *p = buf;
    int n = 0;
    while (*p) {
        if (*p++ == ',')
            n++;
    }
    free(buf);
    return n;
}
