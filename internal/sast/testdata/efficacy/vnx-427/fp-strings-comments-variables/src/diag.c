#include <windows.h>
#include <stdio.h>

/* LoadLibraryA("dbghelp.dll") would search the current directory. */
// setenv("PATH", ".:/usr/bin", 1);
void diagnose(const wchar_t *full_path)
{
    printf("never call LoadLibraryA(\"dbghelp.dll\") without a path\n");
    puts("dlopen(\"./plugins/libauth.so\") is unsafe");
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    HMODULE h = LoadLibraryW(full_path);
    MyLoadLibraryA("dbghelp.dll");
    (void)h;
}
