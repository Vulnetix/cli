#include <alloca.h>
#include <stdlib.h>
#include <string.h>

void tmp(size_t n)
{
    char *scratch = alloca(n);
    memset(scratch, 0, n);
~>    free(scratch);
}
