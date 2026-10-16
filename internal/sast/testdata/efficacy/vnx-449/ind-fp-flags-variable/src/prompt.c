#include <windows.h>

int AskUser(HWND hwnd, LPCWSTR text, BOOL destructive)
{
    UINT flags = destructive ? (MB_OKCANCEL | MB_ICONWARNING) : MB_OK;
    int r = MessageBoxW(hwnd, text, L"Prompt", flags);
    return r == IDOK;
}
