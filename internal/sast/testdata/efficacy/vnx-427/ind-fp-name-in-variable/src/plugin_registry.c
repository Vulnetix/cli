#include <windows.h>
#include <dlfcn.h>

int load_named(const char *dll_name)
{
    /* LoadLibraryA("payload.dll") would search the working directory. */
    HMODULE h = LoadLibraryA(dll_name);
    return h != NULL;
}
