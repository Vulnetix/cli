#include <stdio.h>

int ask(void)
{
    int c;
    printf("continue? ");
~>    fflush(stdin);
    c = getchar();
    return c == 'y';
}
