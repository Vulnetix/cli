#include <stdlib.h>
#include <string.h>

char *dup_name(const char *name)
{
    char buf[64];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *out = malloc(strlen(buf) + 1);
    if (out)
        memcpy(out, buf, strlen(buf) + 1);
    return out;
}
