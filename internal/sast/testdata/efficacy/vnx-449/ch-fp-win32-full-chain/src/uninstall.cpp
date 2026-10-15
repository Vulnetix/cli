#include <windows.h>

int AskUninstall(HWND h)
{
    int rc = MessageBoxA(h, "Remove user data too?", "Uninstall", MB_YESNOCANCEL | MB_ICONQUESTION);
    if (rc == IDYES) {
        return 2;
    } else if (rc == IDNO) {
        return 1;
    } else if (rc == IDCANCEL) {
        return 0;
    }
    return 0;
}
