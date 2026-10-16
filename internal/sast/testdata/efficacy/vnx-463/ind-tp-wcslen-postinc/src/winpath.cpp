#include <cwchar>
#include <cstdio>

void append_sep(wchar_t *wbuf)
{
    size_t len = wcslen(wbuf);
~>    wbuf[len++] = L'\\';
    std::fwprintf(stdout, L"%ls\n", wbuf);
}
