#define _GNU_SOURCE
#include <string.h>

const char *last_line(const char *buf, size_t len)
{
    const char *nl = memrchr(buf, '\n', len - 1);
~>    return nl + 1;
}
