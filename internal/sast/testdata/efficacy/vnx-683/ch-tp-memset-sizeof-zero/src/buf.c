#include <string.h>

void clear(char *buf, size_t n)
{
    char local[64];
~>    memset(local, sizeof(local), 0);
~>    memset(buf, n, 0);
}
