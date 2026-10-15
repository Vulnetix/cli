#include <stdlib.h>

void append(char **buf, size_t *len, char c)
{
    char *tmp;
    tmp = realloc(*buf, *len + 2);
~>    tmp[*len] = c;
    tmp[*len + 1] = '\0';
    *buf = tmp;
    (*len)++;
}
