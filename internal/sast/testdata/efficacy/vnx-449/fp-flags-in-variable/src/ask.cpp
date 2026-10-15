#include <windows.h>

bool Ask(HWND h, LPCTSTR text, UINT buttons)
{
    int r = MessageBox(h, text, TEXT("Question"), buttons);
    return r == IDOK || r == IDYES;
}
