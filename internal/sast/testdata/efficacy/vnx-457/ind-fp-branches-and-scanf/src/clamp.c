#include <stdio.h>

int read_clamped(void)
{
    int x;
    int r;

    if (scanf("%d", &x) != 1)
        return -1;
    if (x > 100)
        r = 100;
    else
        r = x;
    return r;
}
