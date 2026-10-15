#include <comcat.h>
#include "plugin.h"

BEGIN_CATEGORY_MAP(CFileHelper)
~>    IMPLEMENTED_CATEGORY(CATID_SafeForScripting)
~>    IMPLEMENTED_CATEGORY( CATID_SafeForInitializing )
END_CATEGORY_MAP()

HRESULT RegisterSafety()
{
    ICatRegister *pcr = NULL;
    HRESULT hr = CoCreateInstance(CLSID_StdComponentCategoriesMgr, NULL, CLSCTX_INPROC_SERVER, IID_ICatRegister, (void **)&pcr);
    if (FAILED(hr))
        return hr;
    CATID rgcatid[1];
~>    rgcatid[0] = CATID_SafeForScripting;
    hr = pcr->RegisterClassImplCategories(CLSID_FileHelper, 1, rgcatid);
~>    hr = pcr->RegisterClassImplCategories(CLSID_FileHelper, 1, (CATID *)&CATID_SafeForInitializing);
    pcr->Release();
    return hr;
}
