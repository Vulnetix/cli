#include <wchar.h>
#include <stdlib.h>

void set_title(const wchar_t *src)
{
    wchar_t dst[64];
    wchar_t alt[32];
    wcsncpy(dst, src, sizeof(dst) / sizeof(dst[0]));
    wcsncpy(alt, src, _countof(alt));
}
