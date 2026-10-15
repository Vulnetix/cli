#include <stdio.h>

void usage(void)
{
again:
    puts("press a key");
    printf("%s\n", "then goto again;");
    puts("x"); /* goto again; */
}
