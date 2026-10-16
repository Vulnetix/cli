#include <stdlib.h>
#include <string.h>
#include <wchar.h>

wchar_t *wdup(const wchar_t *src)
{
    size_t n = wcslen(src) + 1;
    wchar_t *dst = malloc(n * sizeof(wchar_t));
    if (!dst)
        return NULL;
    memcpy(dst, src, n * sizeof(*dst));
    return dst;
}
