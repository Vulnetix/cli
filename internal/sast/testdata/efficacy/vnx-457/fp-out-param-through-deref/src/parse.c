#include <stdlib.h>

int parse_mem(const char *value, long long *res)
{
    int err;
    *res = parse_bytes(value, &err);
    if (!err)
        return 1;
    return 0;
}
