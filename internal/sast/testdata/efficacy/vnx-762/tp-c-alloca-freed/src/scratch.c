#include <alloca.h>
#include <stdlib.h>

int checksum(const char *in, size_t n)
{
    char *tmp = alloca(n);
    memcpy(tmp, in, n);
    int s = sum(tmp, n);
~>    free(tmp);
    return s;
}
