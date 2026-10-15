#include <string.h>

void join_path(char *buf, const char *name)
{
    size_t n = strlen(buf);
    buf[n] = '/';
    strcpy(buf + n + 1, name);
}
