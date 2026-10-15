#include <windows.h>
#include <cstring>

bool same(const char *a, const char *b)
{
    return _stricmp(a, b) == 0;
}
