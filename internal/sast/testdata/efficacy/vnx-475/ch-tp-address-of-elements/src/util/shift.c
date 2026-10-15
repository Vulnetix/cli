#include <string.h>

void shift(char *buf, size_t n)
{
~>    memcpy(&buf[0], &buf[1], n - 1);
}
