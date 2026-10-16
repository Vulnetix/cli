#include <string.h>
#include <wchar.h>

void move_title(wchar_t *dst, const wchar_t *src)
{
    size_t chars = wcslen(src);
~>    memmove(dst, src, wcslen(src));
    dst[chars] = L'\0';
}
