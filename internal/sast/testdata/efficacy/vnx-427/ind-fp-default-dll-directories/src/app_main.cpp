#include <windows.h>

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show)
{
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);

    HMODULE helper = LoadLibraryW(L"acmehelper.dll");
    if (!helper) {
        return 1;
    }
    HMODULE k32 = LoadLibraryA("kernel32.dll");
    return RunMessageLoop(inst, show, helper, k32);
}
