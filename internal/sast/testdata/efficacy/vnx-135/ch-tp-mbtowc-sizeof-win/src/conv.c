#include <windows.h>

void widen(const char *in)
{
    WCHAR wbuf[MAX_PATH];
~>    MultiByteToWideChar(CP_UTF8, 0, in, -1,
                        wbuf, sizeof(wbuf));
}
