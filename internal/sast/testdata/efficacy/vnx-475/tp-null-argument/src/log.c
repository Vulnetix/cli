#include <stdio.h>
#include <string.h>

void report(char *dst)
{
~>    printf("user=%s\n", NULL);
~>    memcpy(dst, NULL, 0);
~>    size_t n = strlen(NULL);
    (void)n;
}
