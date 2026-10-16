#include <windows.h>
#include <string>

typedef int (WINAPI *ScanInitFn)(const wchar_t *configPath);

bool ScannerHost::Start(const std::wstring &configPath)
{
~>    HMODULE engine = LoadLibraryW(L"scanengine.dll");
    if (engine == nullptr) {
        log_.Error(L"scan engine not available: %lu", GetLastError());
        return false;
    }
    auto init = reinterpret_cast<ScanInitFn>(GetProcAddress(engine, "ScanInit"));
    return init != nullptr && init(configPath.c_str()) == 0;
}
