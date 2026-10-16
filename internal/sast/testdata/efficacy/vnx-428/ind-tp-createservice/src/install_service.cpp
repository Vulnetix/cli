#include <windows.h>

bool InstallAgentService()
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return false;
    }
~>    SC_HANDLE svc = CreateServiceW(scm, L"AcmeAgent", L"Acme Monitoring Agent", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, L"C:\\Program Files\\Acme Agent\\agentsvc.exe", NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return svc != NULL;
}
