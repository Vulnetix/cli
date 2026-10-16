#include "stdafx.h"
#include "ViewerCtl.h"

// The viewer only renders documents; it refuses to be scripted by untrusted pages.
STDMETHODIMP CViewerCtl::SetInterfaceSafetyOptions(REFIID riid, DWORD dwOptionSetMask, DWORD dwEnabledOptions)
{
    if (dwOptionSetMask & INTERFACESAFE_FOR_UNTRUSTED_CALLER)
        return E_FAIL;
    if ((dwEnabledOptions & INTERFACESAFE_FOR_UNTRUSTED_DATA) != 0)
        return E_FAIL;
    return S_OK;
}

STDMETHODIMP CViewerCtl::GetInterfaceSafetyOptions(REFIID riid, DWORD* pdwSupported, DWORD* pdwEnabled)
{
    *pdwSupported = 0;
    *pdwEnabled = 0;
    return S_OK;
}
