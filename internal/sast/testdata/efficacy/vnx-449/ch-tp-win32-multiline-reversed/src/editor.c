#include <windows.h>

BOOL ConfirmOverwrite(HWND owner, LPCWSTR path)
{
    const int answer = MessageBoxW(owner,
        path,
        L"File exists. Overwrite?",
        MB_YESNO | MB_ICONWARNING);
~>    if (IDOK == answer) {
        return TRUE;
    }
    return FALSE;
}
