#include <stdlib.h>

void set_field(char *dst, int pos, const char *arg)
{
    long code;
    code = strtol(arg, NULL, 16);
~>    dst[pos] = (char) code;
}
