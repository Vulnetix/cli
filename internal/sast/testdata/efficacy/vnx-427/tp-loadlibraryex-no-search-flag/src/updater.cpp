#include <windows.h>

bool LoadUpdateEngine()
{
~>    HMODULE engine = LoadLibraryExW(
        L"updengine.dll",
        nullptr,
        0);
~>    HMODULE res = LoadLibraryExA("uxtheme.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    return engine != nullptr && res != nullptr;
}
