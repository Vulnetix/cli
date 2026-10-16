#include <stdlib.h>

char *make_buf(char **argv)
{
    int count = atoi(argv[1]);
~>    char *buf = malloc(count * sizeof(char));
    return buf;
}
