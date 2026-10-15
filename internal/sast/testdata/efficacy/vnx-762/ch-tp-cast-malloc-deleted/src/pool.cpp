#include <cstdlib>
#include <cstring>

void copy_block(const char *src, std::size_t n)
{
    char *dst = static_cast<char *>(std::malloc(n));
    std::memcpy(dst, src, n);
~>    delete[] dst;
}

void dup_name(const char *src)
{
    char *name = strdup(src);
~>    delete name;
}
