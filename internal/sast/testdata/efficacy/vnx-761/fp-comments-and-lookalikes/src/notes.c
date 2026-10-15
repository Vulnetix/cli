#include <stdio.h>
#include <stdlib.h>

/* Never call free(p + 1): free() needs the pointer malloc returned. */
// free(buf + off) would corrupt the heap.
void explain(void)
{
    puts("do not free(p + 1)");
}

void advance_other(size_t n)
{
    char *p = malloc(n);
    char *cursor = p;
    cursor++;
    free(p);
}
