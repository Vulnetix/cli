#include <stdlib.h>
#include <string.h>

char *join(const char *a, const char *b)
{
    char *out = malloc(strlen(a) + strlen(b) + 1);
    if (out == NULL)
        return NULL;
~>    strcat(out, a);
    strcat(out, b);
    return out;
}
