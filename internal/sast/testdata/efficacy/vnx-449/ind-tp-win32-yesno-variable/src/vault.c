#include <windows.h>
#include "vault.h"

void OnClearPasswords(HWND hWnd)
{
    int answer = MessageBoxW(hWnd,
                             L"Delete all saved passwords?",
                             L"Password Vault",
                             MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
~>    if (answer == IDOK) {
        Vault_ClearAll();
        SetStatusText(hWnd, L"Vault cleared");
    }
}
