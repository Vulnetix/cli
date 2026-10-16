#include <stdio.h>

int ask(void)
{
    int c;
    printf("Continue? ");
~>    fflush(stdin);
    c = getchar();
    return c == 'y';
}
