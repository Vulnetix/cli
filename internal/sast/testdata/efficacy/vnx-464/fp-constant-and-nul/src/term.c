#include <string.h>

void term(char *buf, size_t n)
{
    buf[n] = '\0';
    buf[0] = 'x';
}
