#include <stdlib.h>

void first(char *p)
{
    free(p);
}

void second(char *p)
{
    free(p);
}

void third(char *a, char *b)
{
    free(a);
    free(b);
}
