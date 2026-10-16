#include <stddef.h>

char *trim_right(char *p, size_t n)
{
    char *end = p + n - 1;
~>    while (*end = ' ')
        end--;
    return p;
}
