#include <windows.h>

void InitPlugins()
{
~>    SetDllDirectoryW(L"plugins");
~>    SetDllDirectoryA(".\\addons");
    HMODULE h = LoadLibraryExW(L"C:\\Program Files\\Acme\\core.dll", nullptr, 0);
    (void)h;
}
