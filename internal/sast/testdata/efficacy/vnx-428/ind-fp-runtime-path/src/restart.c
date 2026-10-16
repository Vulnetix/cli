#include <windows.h>
#include <stdio.h>

int restart_from_install_dir(const char *install_dir)
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH * 2];

    snprintf(cmd, sizeof(cmd), "\"%s\\agent.exe\" --run", install_dir);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
    ShellExecuteA(NULL, "open", "C:\\Program Files\\Acme\\readme.html", NULL, NULL, SW_SHOW);
    return 0;
}
