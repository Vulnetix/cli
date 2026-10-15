#include <cstring>
#include <cwchar>

void build(char *dst, const char *dir, const wchar_t *wsrc, wchar_t *wdst)
{
~>    std::strcat(dst, dir);
~>    wcscpy(wdst, wsrc);
~>    strcat (dst, getenv("SUFFIX"));
}
