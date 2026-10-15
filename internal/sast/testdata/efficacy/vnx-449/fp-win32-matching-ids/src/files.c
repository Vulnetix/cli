#include <windows.h>

void on_delete(HWND hwnd, const wchar_t *path)
{
    if (MessageBoxW(hwnd, L"Delete this file?", L"Confirm", MB_YESNO | MB_ICONWARNING) == IDYES) {
        DeleteFileW(path);
    }
    int r = MessageBox(hwnd, TEXT("Save first?"), TEXT("Save"), MB_OKCANCEL);
    if (r == IDCANCEL)
        return;
    switch (MessageBoxA(hwnd, "Retry?", "Error", MB_RETRYCANCEL)) {
    case IDRETRY:
        retry();
        break;
    case IDCANCEL:
        break;
    }
    MessageBox(hwnd, "Done", "Info", MB_OK);
    int x = compute();
    if (x == IDOK) {
        log_ok();
    }
}
