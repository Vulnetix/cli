#include <windows.h>

BOOL ConfirmRemoveProfile(HWND owner)
{
~>    if (MessageBoxA(owner, "Remove this profile and its keys?", "Uninstall", MB_ICONQUESTION) != IDNO) {
        return TRUE;
    }
    return FALSE;
}
