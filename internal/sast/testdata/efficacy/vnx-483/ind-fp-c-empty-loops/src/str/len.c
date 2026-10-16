#include <stddef.h>

size_t my_strlen(const char *s)
{
    const char *p = s;
    while (*p++);
    return (size_t)(p - s - 1);
}

void spin(volatile int *flag)
{
    int i;
    for (i = 0; i < 1000 && !*flag; i++);
    do {
        i--;
    } while (i > 0);
}
