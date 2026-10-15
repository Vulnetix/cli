#include <windows.h>
#include <shlwapi.h>

BOOL join(LPCSTR base, LPCSTR rel)
{
    char joined[MAX_PATH];
    return PathCombineA(joined, base, rel) != NULL;
}

BOOL canon(LPCWSTR in)
{
    WCHAR out[MAX_PATH + 1];
    return PathCanonicalizeW(out, in);
}
