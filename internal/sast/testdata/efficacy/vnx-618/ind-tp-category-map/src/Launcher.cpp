#include "stdafx.h"
#include "Launcher.h"

BEGIN_CATEGORY_MAP(CLauncher)
~>    IMPLEMENTED_CATEGORY(CATID_SafeForScripting)
END_CATEGORY_MAP()

STDMETHODIMP CLauncher::Run(BSTR cmd)
{
    return ShellExecuteW(NULL, L"open", cmd, NULL, NULL, SW_SHOW) ? S_OK : E_FAIL;
}
