#include <string.h>

void fill(char *buffer, const char *src, char *out, const char *payload, size_t n)
{
    memcpy(buffer, src, n);
    memcpy(out, payload, n);
    strcpy(buffer, payload);
}
