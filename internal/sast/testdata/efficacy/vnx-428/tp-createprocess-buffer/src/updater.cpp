#include <windows.h>
#include <wchar.h>

bool RunUpdater()
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t cmd[MAX_PATH] = L"C:\\Program Files\\Acme\\updater.exe /silent";
~>    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    wchar_t helper[MAX_PATH];
    wcscpy_s(helper, MAX_PATH, L"C:\\Program Files\\Acme\\helper.exe");
~>    ok = ok && CreateProcessW(NULL, helper, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
~>    WinExec("C:\\Program Files\\Acme\\tray.exe", SW_HIDE);
    return ok;
}
