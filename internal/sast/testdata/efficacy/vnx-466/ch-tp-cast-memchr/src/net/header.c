#include <string.h>
#include <stddef.h>

char *header_value(char *line, size_t len)
{
~>    return (char *)memchr(line, ':', len) + 1;
}
