#include <stdlib.h>

void run(size_t n)
{
    char *p = malloc(n);
    char *start = p;
    *p++ = 'x';
    p = start;
    free(p);
}

// free(buf + 4) would be a bug, but this is a comment
