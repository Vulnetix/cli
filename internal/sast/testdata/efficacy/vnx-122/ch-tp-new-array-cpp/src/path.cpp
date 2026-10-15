#include <cstring>

char *clone_path(const char *src)
{
~>    char *buf = new char[std::strlen(src)];
    std::strcpy(buf, src);
    return buf;
}
