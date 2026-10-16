#include <stdio.h>
#include <string.h>

void declared(const char *s)
{
    size_t len = strlen(s);
    double ratio = 0.5;
~>    printf("len=%d\n", len);
~>    printf("ratio=%d\n", ratio);
}
