#include <stdlib.h>

#define HEADER 16

void my_free(void *ptr)
{
    free((char *)ptr - HEADER);
}

void free_all(char **items, int n)
{
    for (int i = 0; i < n; i++)
        free(items[i]);
}

void free_first(char *buf)
{
    free(&buf[0]);
}

void release_str(void *s)
{
    sdsfree(s);
}
