#include <stdlib.h>
int peek(const char *s)
{
    unsigned long addr = strtoul(s, NULL, 0);
~>    int *target = (int *)addr;
    return *target;
}
