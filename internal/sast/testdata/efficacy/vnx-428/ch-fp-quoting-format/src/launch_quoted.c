#include <windows.h>
#include <stdio.h>

int launch(STARTUPINFOW *si, PROCESS_INFORMATION *pi)
{
    wchar_t cmd[MAX_PATH * 2];
    swprintf_s(cmd, MAX_PATH * 2, L"\"%s\" --service", L"C:\\Program Files\\Acme Agent\\agent.exe");
    return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
}

int launch_two(STARTUPINFOA *si, PROCESS_INFORMATION *pi)
{
    char line[512];
    snprintf(line, sizeof line, "\"%s\" /quiet", "C:\\Program Files\\Acme\\setup.exe");
    return CreateProcessA(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
}
