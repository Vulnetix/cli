#include <string.h>

void set_name(char *dst, size_t n, const char *src)
{
~>    strlcpy(dst, src, n);
~>    strlcat(dst, ".conf", n);
}
