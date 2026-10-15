#include <stdlib.h>

void free_all(char **items, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(items[i]);
    free(items);
    free(*(items + 1));
    free(&items[0]);
}

void rewind_then_free(size_t n)
{
    char *p = malloc(n);
    char *start = p;
    p += 8;
    p = start;
    free(p);
}

void step_back(size_t n)
{
    char *q = malloc(n);
    q++;
    q--;
    free(q);
}

void sds_style(char *s)
{
    sdsfree(s + 1);
    my_free(s + 1);
}
