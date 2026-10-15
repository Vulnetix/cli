#include <stdlib.h>
#include <string.h>

int parse(const char *in)
{
    char *copy = strdup(in);
    int n = (int)strlen(copy);
    free(copy);
    if (n > 10)
        n = 10;
~>    free(copy);
    return n;
}
