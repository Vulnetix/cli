#include <cwchar>
#include <windows.h>

wchar_t *wclone(const wchar_t *s)
{
    wchar_t *out = new wchar_t[wcslen(s) + 1];
    wcscpy(out, s);
    return out;
}

void read_caption(HWND hwnd)
{
    WCHAR caption[260];
    GetWindowTextW(hwnd, caption, _countof(caption));
}
