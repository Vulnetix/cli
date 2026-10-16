#include <windows.h>

bool Watchdog::RestartAgent()
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
~>    BOOL ok = CreateProcessW(NULL, L"C:\\Program Files\\Contoso Backup\\bkagent.exe -daemon", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) {
        return false;
    }
    CloseHandle(pi.hThread);
    agentProcess_ = pi.hProcess;
    return true;
}
