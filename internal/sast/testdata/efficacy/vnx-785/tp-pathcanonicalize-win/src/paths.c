#include <windows.h>
#include <shlwapi.h>

BOOL normalize(const char *input)
{
    char clean[64];
~>    return PathCanonicalizeA(clean, input);
}

BOOL join(LPCWSTR base, LPCWSTR rel)
{
    WCHAR joined[100];
~>    return PathCombineW(joined, base, rel) != NULL;
}

BOOL append(LPSTR dir)
{
    TCHAR tmp[32];
    lstrcpy(tmp, dir);
~>    return PathAppend(tmp, TEXT("logs"));
}
