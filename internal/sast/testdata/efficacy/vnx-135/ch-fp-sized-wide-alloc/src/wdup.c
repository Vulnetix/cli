#include <stdlib.h>
#include <string.h>
#include <wchar.h>

wchar_t *wdup(const wchar_t *src)
{
    size_t n = wcslen(src) + 1;
    wchar_t *copy = malloc((wcslen(src) + 1) * sizeof(wchar_t));
    memcpy(copy, src, n * sizeof(*src));
    return copy;
}
