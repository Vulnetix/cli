#include <stdio.h>

/* free(&local) is undefined behaviour */
// free("literal") too
void explain(void)
{
    puts("never free(&x)");
}
