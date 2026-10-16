#include <stdlib.h>

int parse_int(const char *s, int **out)
{
    int value = atoi(s);
~>    *out = &value;
    return 0;
}

int make_buf(char **result)
{
    char buf[64];
    buf[0] = 0;
~>    *result = buf;
    return 0;
}
