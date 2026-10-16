#include <cstring>

void trim_nl(char *s)
{
    size_t len = strlen(s);
~>    s[len - 1] = '\0';
}
