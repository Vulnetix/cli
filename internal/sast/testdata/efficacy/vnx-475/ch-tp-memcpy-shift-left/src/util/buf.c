#include <string.h>

void drop_first(char *buf, size_t len)
{
~>    memcpy(buf, buf + 1, len - 1);
}

void trim_leading(char *s)
{
~>    strcpy(s, s + 2);
}
