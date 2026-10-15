#include <stdio.h>

void doc(void)
{
    char a[8];
    char b[16];
    /* snprintf(a, sizeof(b), "x"); would be the bug */
    puts("memset(a, 0, sizeof(b))");
    (void)a; (void)b;
}
