#include <cstring>

void trim_slash(char *path)
{
    size_t len = strlen(path);
~>    path[len - 1] = '\0';
}

void trim_crlf(char *s)
{
    int n = strlen(s);
    if (s[n - 1] == '\r')
~>        s[n - 1] = 0;
}
