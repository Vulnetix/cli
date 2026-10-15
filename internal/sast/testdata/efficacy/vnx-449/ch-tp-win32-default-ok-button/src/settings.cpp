#include <windows.h>

void ResetSettings(HWND hWnd)
{
~>    if (MessageBox(hWnd, TEXT("Reset all settings?"), TEXT("Settings"), MB_ICONQUESTION) == IDYES) {
        ClearRegistryKeys();
    }
}
