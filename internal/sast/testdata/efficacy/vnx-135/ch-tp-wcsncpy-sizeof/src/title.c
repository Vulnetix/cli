#include <wchar.h>

void set_title(const wchar_t *src)
{
    wchar_t dst[64];
~>    wcsncpy(dst, src, sizeof(dst));
}
