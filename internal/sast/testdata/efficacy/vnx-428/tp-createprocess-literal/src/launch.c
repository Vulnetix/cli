#include <windows.h>

int start_agent(void)
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
~>    if (!CreateProcessA(NULL, "C:\\Program Files\\Acme Agent\\agent.exe --service", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
~>    CreateProcess(
        NULL,
        TEXT("C:\\Program Files (x86)\\Acme\\bin\\collector.exe"),
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    return 0;
}
