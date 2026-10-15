#include <stdio.h>
#include <string.h>

void report(size_t n)
{
~>    printf("user: %s\n", NULL);
~>    memset(NULL, 0, n);
}
