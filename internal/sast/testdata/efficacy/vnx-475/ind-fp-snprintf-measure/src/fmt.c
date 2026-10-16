#include <stdio.h>
#include <stdlib.h>

char *format_id(const char *prefix, int id)
{
    int n = snprintf(NULL, 0, "%s-%d", prefix, id);
    char *out = malloc((size_t)n + 1);
    if (out)
        snprintf(out, (size_t)n + 1, "%s-%d", prefix, id);
    return out;
}
