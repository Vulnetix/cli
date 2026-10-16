#include <cstdlib>
#include <cstring>

void copy(const char *src, size_t len)
{
    char *dst = (char *)malloc(len);
    memcpy(dst, src, len);
~>    delete[] dst;
}
