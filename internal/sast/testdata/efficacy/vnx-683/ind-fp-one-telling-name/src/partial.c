#include <string.h>

void p(char *src, char *buf, char *out, char *tmp, size_t n)
{
    memcpy(src, buf, n);
    memcpy(tmp, out, n);
    strcat(buf, out);
    strncpy(tmp, src, n);
}
