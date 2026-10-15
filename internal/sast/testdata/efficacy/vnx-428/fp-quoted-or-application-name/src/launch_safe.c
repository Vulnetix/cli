#include <windows.h>

int start_safely(STARTUPINFOW *si, PROCESS_INFORMATION *pi)
{
    CreateProcessW(NULL, L"\"C:\\Program Files\\Acme Agent\\agent.exe\" --service", NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
    CreateProcessW(L"C:\\Program Files\\Acme\\agent.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
    CreateProcessW(NULL, L"C:\\Tools\\agent.exe --service now", NULL, NULL, FALSE, 0, NULL, NULL, si, pi);
    ShellExecuteW(NULL, L"open", L"C:\\Program Files\\Acme\\agent.exe", NULL, NULL, SW_SHOW);
    WinExec("\"C:\\Program Files\\Acme\\tray.exe\"", SW_HIDE);
    CreateServiceW(scm, L"AcmeSvc", L"Acme Service", SERVICE_ALL_ACCESS, @@sample:S[E]RV[I]CE[_]WI[N]32[_]OW[N][_]P[R]OC[E]SS@@,
                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                   L"\"C:\\Program Files\\Acme Monitor\\svc.exe\"", NULL, NULL, NULL, NULL, NULL);
    return 0;
}
