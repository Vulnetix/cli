#include <windows.h>
#include <shlwapi.h>

bool normalize(const char *input)
{
    char clean[64];
~>    if (!PathCanonicalizeA(clean, input))
        return false;
    return true;
}
