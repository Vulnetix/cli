#include <string.h>

void g(const char *src)
{
    char *a, *b;
    a = b = (char *)src;
    int *cnt;
    if ((cnt = get_counts()) == NULL) return;
    *cnt = 0;
}
