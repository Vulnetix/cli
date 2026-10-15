#include <stdlib.h>
#include <wchar.h>

wchar_t *dup_wide(const wchar_t *src)
{
~>    wchar_t *dst = malloc(wcslen(src) + 1);
    wcscpy(dst, src);
    return dst;
}

char *to_mb(const wchar_t *w)
{
~>    char *out = (char *)malloc(wcslen(w) + 1);
    wcstombs(out, w, wcslen(w) + 1);
    return out;
}
