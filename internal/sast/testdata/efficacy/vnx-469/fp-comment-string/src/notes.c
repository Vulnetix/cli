#include <stdio.h>
#include <stdlib.h>

void explain(void)
{
    char *dst = malloc(8);
    char *src = malloc(8);
    /* never compute dst - src: they are different allocations */
    // size_t bad = dst - src;
    puts("dst - src is undefined");
    free(dst);
    free(src);
}
