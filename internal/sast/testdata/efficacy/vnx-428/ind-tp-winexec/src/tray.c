#include <windows.h>

void on_sync_now_clicked(HWND hwnd)
{
~>    UINT rc = WinExec("C:\\Program Files (x86)\\Fabrikam\\sync.exe --once", SW_HIDE);
    if (rc <= 31) {
        MessageBoxA(hwnd, "Sync could not be started", "Fabrikam", MB_ICONERROR);
    }
}
