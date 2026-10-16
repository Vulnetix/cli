#include <windows.h>

int launch(void)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    wchar_t args[] = L"agent.exe --run";

    if (!CreateProcessW(L"C:\\Program Files\\Acme Agent\\agent.exe", args, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
    WinExec("C:\\Tools\\sync.exe /once", SW_HIDE);
    return 0;
}
