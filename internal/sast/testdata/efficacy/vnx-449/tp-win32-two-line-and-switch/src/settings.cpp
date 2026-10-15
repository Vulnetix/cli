#include <windows.h>

void Settings::OnReset(HWND hwnd)
{
    int answer = MessageBox(hwnd,
                            TEXT("Reset all security settings to defaults?"),
                            TEXT("Reset"),
                            MB_YESNOCANCEL | MB_ICONQUESTION);
~>    if (answer != IDOK)
        return;
    ResetSecurityDefaults();
}

void Settings::OnUninstall(HWND hwnd)
{
    switch (MessageBoxA(hwnd, "Remove the service?", "Uninstall", MB_YESNO)) {
~>    case IDOK:
        RemoveService();
        break;
    case IDNO:
        break;
    }
}
