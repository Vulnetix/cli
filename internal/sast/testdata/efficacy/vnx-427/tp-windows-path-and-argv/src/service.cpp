#include <windows.h>
#include <cstdlib>

int wmain(int argc, wchar_t **argv)
{
~>    SetEnvironmentVariableW(L"PATH", L"bin;C:\\Windows\\System32");
    if (argc > 2) {
        const char *libdir = getenv("APP_UNUSED");
        char *plugin_dir = (char *)argv[2];
~>        setenv("LD_LIBRARY_PATH", plugin_dir, 1);
    }
~>    _putenv("PATH=;C:\\Windows\\System32");
    return 0;
}
