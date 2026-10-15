#include <stdlib.h>

char *make(char **argv)
{
~>    return malloc(atoi(argv[2]));
}
