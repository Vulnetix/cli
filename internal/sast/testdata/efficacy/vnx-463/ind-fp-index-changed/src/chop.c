#include <string.h>

void mark_last(char *s)
{
    size_t n = strlen(s);
    if (n == 0)
        return;
    n = n - 1;
    s[n] = '*';
}
