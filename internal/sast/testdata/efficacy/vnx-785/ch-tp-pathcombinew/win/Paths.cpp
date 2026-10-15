#include <windows.h>
#include <shlwapi.h>

HRESULT BuildPluginPath(LPCWSTR dir, LPCWSTR file, std::wstring &result)
{
    WCHAR szFull[128];
~>    if (!PathCombineW(szFull,
                      dir,
                      file)) {
        return E_FAIL;
    }
    result.assign(szFull);
    return S_OK;
}
