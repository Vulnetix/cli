#include "util.h"

unsigned long long conv(const char *cur, char **end)
{
    return malloc_strtoumax(cur, end, 0);
}
