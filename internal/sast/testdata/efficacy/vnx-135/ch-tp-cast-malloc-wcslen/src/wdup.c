#include <stdlib.h>
#include <wchar.h>

wchar_t *wdup(const wchar_t *src)
{
~>    wchar_t *copy = (wchar_t *)malloc(wcslen(src) + 1);
    wcscpy(copy, src);
    return copy;
}
