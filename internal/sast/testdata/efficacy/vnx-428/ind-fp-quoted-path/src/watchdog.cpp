#include <windows.h>

bool Watchdog::RestartAgent()
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    return CreateProcessW(NULL, L"\"C:\\Program Files\\Contoso Backup\\bkagent.exe\" -daemon", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) != FALSE;
}

void SyncOnce()
{
    WinExec("\"C:\\Program Files\\Fabrikam\\sync.exe\" --once", SW_HIDE);
}
