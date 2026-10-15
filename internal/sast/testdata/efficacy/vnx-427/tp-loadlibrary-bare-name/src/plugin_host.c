#include <windows.h>
#include <tchar.h>

typedef BOOL (WINAPI *MiniDumpFn)(HANDLE, DWORD, HANDLE, int, void *, void *, void *);

int load_helpers(void)
{
~>    HMODULE dbg = LoadLibraryA("dbghelp.dll");
~>    HMODULE ver = LoadLibraryW(L"version.dll");
~>    HMODULE wts = LoadLibrary(TEXT("wtsapi32.dll"));
~>    HMODULE prov = LoadLibrary( _T( "cryptsp.dll" ) );
    if (!dbg || !ver || !wts || !prov) {
        return -1;
    }
    return 0;
}
