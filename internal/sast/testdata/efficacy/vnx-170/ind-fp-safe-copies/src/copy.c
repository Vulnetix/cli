#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void set_label(char *label, size_t size, const char *src)
{
    snprintf(label, size, "%s", src);
}

char *dup_with_nul(const char *src)
{
    size_t n = strlen(src) + 1;
    char *out = malloc(n);
    if (out)
        memcpy(out, src, strlen(src) + 1);
    return out;
}

void set_default(char *dst)
{
    strncpy(dst, "guest", 6);
}

/* strncpy(dst, src, sizeof(dst)) would not terminate */
