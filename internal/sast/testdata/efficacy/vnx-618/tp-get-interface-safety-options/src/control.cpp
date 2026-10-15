#include "control.h"

STDMETHODIMP CDownloader::GetInterfaceSafetyOptions(REFIID riid, DWORD *pdwSupportedOptions, DWORD *pdwEnabledOptions)
{
    if (!pdwSupportedOptions || !pdwEnabledOptions)
        return E_POINTER;
~>    *pdwSupportedOptions = INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA;
~>    *pdwEnabledOptions   = INTERFACESAFE_FOR_UNTRUSTED_CALLER|INTERFACESAFE_FOR_UNTRUSTED_DATA;
    return S_OK;
}

STDMETHODIMP CDownloader::SetInterfaceSafetyOptions(REFIID riid, DWORD dwOptionSetMask, DWORD dwEnabledOptions)
{
    m_dwSafety = dwEnabledOptions & INTERFACESAFE_FOR_UNTRUSTED_CALLER;
    return S_OK;
}
