#include <cstring>
#include <cwchar>

void copy_title(wchar_t *dst, const wchar_t *src)
{
~>    std::memcpy(dst, src, wcslen(src) + 1);
~>    memmove(dst, src, wcslen(src));
}
