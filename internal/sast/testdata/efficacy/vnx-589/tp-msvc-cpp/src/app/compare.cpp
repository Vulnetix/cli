#include <cstring>
#include <cstdlib>

bool same(const char *a, const char *b, int n)
{
    char buf[16];
~>    itoa(n, buf, 10);
~>    return _stricmp(a, b) == 0 &&
~>        _strnicmp(a, buf, 3) == 0;
}
