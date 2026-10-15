#include <wchar.h>

void copy(wchar_t *dst, const wchar_t *src)
{
    wmemcpy(dst, src, wcslen(src) + 1);
}
