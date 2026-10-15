#include <cstring>
#include <cstddef>

void copy_tail(char *dst, const char *src, size_t total, size_t consumed)
{
~>    size_t remaining = total - consumed;
    std::memcpy(dst, src + consumed, remaining);
}
