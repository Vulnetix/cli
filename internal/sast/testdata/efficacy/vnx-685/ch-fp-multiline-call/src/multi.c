#include <stdio.h>

void show(int a, int b)
{
    printf("%d %d\n",
           a, b);
    fprintf(stderr,
            "%s\n", "done");
}
