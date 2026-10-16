#include <string.h>
#include <stdlib.h>
#include <stddef.h>

ptrdiff_t name_offset(const char *a, const char *b)
{
    char *left = strdup(a);
    char *right = strdup(b);
~>    ptrdiff_t d = right - left;
    free(left);
    free(right);
    return d;
}
