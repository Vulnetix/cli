#include <stdlib.h>
int count(const char *s)
{
    unsigned long n = strtoul(s, NULL, 10);
    long k = atol(s);
    return (int)(n + k);
}
