#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

void label(const wchar_t *who, const char *mb)
{
    wchar_t buf[64];
    wchar_t name[32];
~>    wcsncpy(buf, who, sizeof(buf));
~>    swprintf(name, sizeof name, L"%ls", who);
~>    mbstowcs(buf, mb, sizeof(buf));
~>    fgetws(buf, sizeof(buf), stdin);
}
