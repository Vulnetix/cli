#include <stdlib.h>

void mark(char seen[256], const char *arg)
{
    seen[atoi(arg) & 0xff] = 'x';
    int n = atoi(arg);
    seen[n % 256] = 1;
}
