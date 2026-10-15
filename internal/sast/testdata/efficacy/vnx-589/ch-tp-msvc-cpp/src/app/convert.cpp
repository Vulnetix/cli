#include <cstdlib>
#include <cstring>

int compare(const char *a, const char *b)
{
    char buf[32];
~>    _itoa(42, buf, 10);
~>    return _stricmp(a, b);
}
