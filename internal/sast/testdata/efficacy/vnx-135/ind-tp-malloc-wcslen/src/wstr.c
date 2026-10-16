#include <stdlib.h>
#include <wchar.h>

wchar_t *wdup(const wchar_t *src)
{
~>    wchar_t *dst = malloc(wcslen(src) + 1);
    if (!dst)
        return NULL;
    wcscpy(dst, src);
    return dst;
}
