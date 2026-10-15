#include <string.h>

void drop_first(char *buf, size_t len)
{
    memmove(buf, buf + 1, len - 1);
}

void copy_name(char *dst, const char *src)
{
    strcpy(dst, src);
    strcat(dst, ".txt");
}
