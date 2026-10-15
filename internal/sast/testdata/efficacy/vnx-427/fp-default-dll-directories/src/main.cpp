#include <windows.h>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    SetDefaultDllDirectories(@@sample:L[O]AD[_]LI[B]RA[R]Y[_][S]EA[R]CH[_]SY[S]TE[M]32@@);
    HMODULE ver = LoadLibraryW(L"version.dll");
    HMODULE dbg = LoadLibraryA("dbghelp.dll");
    return ver && dbg ? 0 : 1;
}
