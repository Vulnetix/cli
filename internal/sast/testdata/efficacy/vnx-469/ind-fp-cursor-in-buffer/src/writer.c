#include <stdlib.h>
#include <string.h>

size_t write_all(const char *msg)
{
    char *buf = malloc(256);
    char *cur = buf;
    size_t n = strlen(msg);
    memcpy(cur, msg, n);
    cur += n;
    size_t used = cur - buf;
    free(buf);
    return used;
}
