#include <stdlib.h>
#include <string.h>

char *dup_line(const char *s, size_t n)
{
    char *copy = malloc(n + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, s, n);
    copy[n] = '\0';
    return copy;
}
