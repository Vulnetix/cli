#include <ctype.h>
#include <stdio.h>

int count_alpha(void)
{
    int c, n = 0;
    while ((c = getchar()) != EOF)
        if (isalpha(c))
            n++;
    return n;
}
