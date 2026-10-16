#include "Safety.h"

#define SAFETY_ALL (INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA)
extern const GUID CATID_SafeForScripting;
DEFINE_GUID(CATID_SafeForInitializing, 0x7DD95802, 0x9882, 0x11CF, 0x9F, 0xA9, 0x00, 0xAA, 0x00, 0x6C, 0x42, 0xC4);

STDMETHODIMP CWidget::SetInterfaceSafetyOptions(REFIID riid, DWORD dwOptionSetMask, DWORD dwEnabledOptions)
{
    if ((dwOptionSetMask & INTERFACESAFE_FOR_UNTRUSTED_CALLER) == 0)
        return E_FAIL;
    if (dwEnabledOptions & INTERFACESAFE_FOR_UNTRUSTED_DATA)
        return S_OK;
    return E_INVALIDARG;
}
// We deliberately do not call IMPLEMENTED_CATEGORY(CATID_SafeForScripting) here.
static const char* kNote = "never use IObjectSafetyImpl<T, INTERFACESAFE_FOR_UNTRUSTED_CALLER>";
