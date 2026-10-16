#include <stdlib.h>

int grow(char **out, size_t next)
{
    char *tmp = realloc(*out, next);
    if (tmp == NULL)
        return -1;
    *out = tmp;
    return 0;
}
