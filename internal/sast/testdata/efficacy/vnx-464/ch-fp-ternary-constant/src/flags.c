#include <stdlib.h>

void set_flags(char out[4], char **argv)
{
    out[0] = atoi(argv[1]) ? 'Y' : 'N';
    out[1] = atoi(argv[2]) > 0 ? '+' : '-';
    out[2] = '\0';
}
