#include <stdlib.h>

void cycle(size_t n)
{
    char *p = malloc(n);
    use(p);
    free(p);
    p = malloc(n * 2);
    use(p);
    free(p);
}
