#include <windows.h>

void on_delete(HWND hwnd, const wchar_t *path)
{
~>    if (MessageBoxW(hwnd, L"Delete this file permanently?", L"Confirm", MB_YESNO | MB_ICONWARNING) == IDOK) {
        DeleteFileW(path);
    }
}
