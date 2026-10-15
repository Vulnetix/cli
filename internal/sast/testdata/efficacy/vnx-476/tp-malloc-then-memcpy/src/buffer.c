#include <stdlib.h>
#include <string.h>

char *copy_message(const char *msg, size_t len)
{
    char *out = (char *) malloc(len + 1);
~>    memcpy(out, msg, len);
    out[len] = '\0';
    return out;
}

int *make_counts(size_t n)
{
    int *counts;
    counts = calloc(n,
                    sizeof(int));
~>    *counts = 1;
    return counts;
}
