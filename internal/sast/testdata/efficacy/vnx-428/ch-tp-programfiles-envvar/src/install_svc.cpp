#include <windows.h>

SC_HANDLE InstallUpdater(SC_HANDLE scm)
{
~>    return CreateServiceW(scm, L"AcmeUpdate", L"Acme Updater", SERVICE_ALL_ACCESS,
                          @@sample:S[E]RV[I]CE[_]WI[N]32[_]OW[N][_]P[R]OC[E]SS@@, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                          L"%ProgramFiles%\\Acme\\Update Service\\updsvc.exe",
                          NULL, NULL, NULL, NULL, NULL);
}
