#include <windows.h>
#include <dlfcn.h>
#include <stdlib.h>

int load_safely(void)
{
    HMODULE a = LoadLibraryW(L"C:\\Windows\\System32\\version.dll");
    HMODULE b = LoadLibraryExW(L"dbghelp.dll", NULL, @@sample:L[O]AD[_]LI[B]RA[R]Y[_][S]EA[R]CH[_]SY[S]TE[M]32@@);
    HMODULE c = LoadLibraryExW(L"wtsapi32.dll", NULL,
                               @@sample:L[O]AD[_]LI[B]RA[R]Y[_][S]EA[R]CH[_]SY[S]TE[M]32@@ | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    HMODULE d = LoadLibraryExA("icons.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    HMODULE k = LoadLibraryA("kernel32.dll");
    HMODULE u = LoadLibrary(TEXT("user32.dll"));
    void *ssl = dlopen("libssl.so.3", RTLD_NOW);
    void *z = dlopen("/usr/lib/x86_64-linux-gnu/libz.so.1", RTLD_NOW);
    void *self = dlopen(NULL, RTLD_NOW);
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    putenv("LD_LIBRARY_PATH=/opt/app/lib");
    setenv("HOME", ".", 1);
    return a && b && c && d && k && u && ssl && z && self;
}
