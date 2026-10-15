#include <windows.h>

int run_tools(STARTUPINFOA *si, PROCESS_INFORMATION *pi)
{
    CreateProcessA(NULL, "C:\\Windows\\System32\\cmd.exe /c \"C:\\Program Files\\Acme\\cleanup.bat\"", NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
    CreateProcessA("C:\\Program Files\\Acme\\tool.exe", "tool.exe --scan C:\\Program Files\\Data", NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
    WinExec("C:\\Tools\\tray.exe C:\\Program Files\\Acme", SW_HIDE);
    return 0;
}
