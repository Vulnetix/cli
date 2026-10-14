#include <windows.h>
#include <tchar.h>
#include <mbstring.h>
#include <wchar.h>

void build_paths(const wchar_t *wuser, const unsigned char *mbuser, LPCSTR ansi, LPCWSTR wide, const TCHAR *t)
{
    wchar_t wbuf[64];
    wchar_t *end;
    unsigned char mbuf[64];
    char abuf[MAX_PATH];
    WCHAR wpath[MAX_PATH];
    TCHAR tbuf[64];

~>    wcscpy(wbuf, wuser);
~>    wcscat(wbuf, wuser);
~>    end = wcpcpy(wbuf, wuser);
~>    _mbscpy(mbuf, mbuser);
~>    _mbscat(mbuf, mbuser);
~>    lstrcpyA(abuf, ansi);
~>    lstrcatW(wpath, wide);
~>    lstrcpy(tbuf, t);
~>    _tcscpy(tbuf, t);
~>    _tcscat(tbuf, t);
}

void read_wide_line(void)
{
    wchar_t input[80];
~>    _getws(input);
}
