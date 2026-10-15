#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

wchar_t *dup_wide(const wchar_t *src)
{
    size_t n = wcslen(src) + 1;
    wchar_t *dst = malloc(n * sizeof(wchar_t));
    memcpy(dst, src, n * sizeof(wchar_t));
    wchar_t *d2 = malloc((wcslen(src) + 1) * sizeof(*d2));
    return dst;
}

void label(const wchar_t *who)
{
    wchar_t buf[64];
    wcsncpy(buf, who, sizeof(buf) / sizeof(buf[0]));
    swprintf(buf, ARRAY_SIZE(buf), L"%ls", who);
    mbstowcs(buf, "abc", _countof(buf));
    wmemset(buf, 0, 64);
    size_t chars = wcslen(buf);
    wchar_t *w = new wchar_t[wcslen(who) + 1];
}
