#include <windows.h>

void read_caption(HWND hwnd, const char *utf8)
{
    WCHAR caption[260];
~>    GetWindowTextW(hwnd, caption, sizeof(caption));
    WCHAR converted[128];
~>    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, converted, sizeof(converted));
    SetWindowTextW(hwnd, converted);
}
