#include <windows.h>

void SecureInit()
{
    SetDllDirectoryW(L"");
    SetDllDirectoryA("C:\\Program Files\\Acme\\bin");
    AddDllDirectory(L"C:\\Program Files\\Acme\\plugins");
    HMODULE p = LoadLibraryExW(L"acmeplugin.dll", nullptr, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    FARPROC f = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlGetVersion");
    HMODULE q = LoadLibraryExA(
        "acmeres.dll",
        NULL,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | @@sample:L[O]AD[_]LI[B]RA[R]Y[_][S]EA[R]CH[_]SY[S]TE[M]32@@);
    (void)p; (void)f; (void)q;
}
