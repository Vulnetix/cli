#include <string.h>

void queue_pop(char *buf, size_t len)
{
~>    memcpy(buf, buf + 1, len - 1);
}
