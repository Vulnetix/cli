#include <stdlib.h>
#include <string.h>

char *bounded_copy(const char *src)
{
    char *buf = malloc(64);
    if (!buf)
        return NULL;
    if (strlen(src) >= 64) {
        free(buf);
        return NULL;
    }
    strcpy(buf, src);
    return buf;
}
