#include <cstring>

char *clone(const char *s)
{
~>    char *p = new char[std::strlen(s)];
    std::strcpy(p, s);
    return p;
}
