#include <stdio.h>

void show(const char *name, int a)
{
~>    fprintf(stderr, "%s: %d of %d\n",
            name, a);
}
