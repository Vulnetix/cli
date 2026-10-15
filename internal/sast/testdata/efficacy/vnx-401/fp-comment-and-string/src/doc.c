#include <stdio.h>

/* buf = realloc(buf, n) leaks on failure; use a temporary. */
// char *p = malloc(n); if (bad) return -1;
void usage(void)
{
    puts("p = realloc(p, n) is unsafe");
}
