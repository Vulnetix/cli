#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

void title(HWND hwnd, LPCSTR caption)
{
    char text[256];

~>    wsprintfA(text, caption);
    SetWindowTextA(hwnd, text);
}

void relay(int fd, va_list ap)
{
    char line[512];
    char out[512];

    if (read(fd, line, sizeof(line) - 1) <= 0)
        return;
~>    vprintf(line, ap);
~>    vsprintf(out, line, ap);
~>    vsnprintf(out, sizeof(out), line, ap);
~>    vsyslog(LOG_NOTICE, line, ap);
}
