#include <stdlib.h>

char *buffers(const char *s)
{
    int n = atoi(s);
    if (n <= 0 || n > 1024)
        return NULL;
    return malloc(n * 8);
}
