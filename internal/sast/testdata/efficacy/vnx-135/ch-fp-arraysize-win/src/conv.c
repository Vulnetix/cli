#include <windows.h>

void widen(const char *in)
{
    WCHAR wbuf[MAX_PATH];
    char narrow[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, in, -1, wbuf, ARRAYSIZE(wbuf));
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, narrow, sizeof(narrow), NULL, NULL);
}
