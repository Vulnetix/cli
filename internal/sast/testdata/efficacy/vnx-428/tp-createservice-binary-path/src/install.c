#include <windows.h>

int install_service(SC_HANDLE scm)
{
~>    SC_HANDLE svc = CreateServiceW(
        scm,
        L"AcmeSvc",
        L"Acme Monitoring Service",
        SERVICE_ALL_ACCESS,
        @@sample:S[E]RV[I]CE[_]WI[N]32[_]OW[N][_]P[R]OC[E]SS@@,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        L"C:\\Program Files\\Acme Monitor\\svc.exe",
        NULL, NULL, NULL, NULL, NULL);
    if (svc == NULL) {
        return -1;
    }
    CloseServiceHandle(svc);
    return 0;
}
