#include <stdlib.h>

char *make(char **argv)
{
    int count = atoi(argv[1]);
    if (count < 0)
        return NULL;
~>    return malloc(count);
}
