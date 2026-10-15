#include <cassert>
#include <cstring>

char *dup_name(const char *name)
{
    size_t len = strlen(name);
    char *copy = new char[len + 1];
    std::memcpy(copy, name, len + 1);
    return copy;
}

void set_tag(char tag[16], const char *src)
{
    size_t n = strlen(src);
    assert(n < 16);
    memcpy(tag, src, n + 1);
}
