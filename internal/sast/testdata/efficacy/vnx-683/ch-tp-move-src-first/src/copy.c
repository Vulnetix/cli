#include <string.h>

void copy(char *dst_buf, const char *src_buf, size_t n)
{
~>    memmove(src_buf, dst_buf, n);
}
