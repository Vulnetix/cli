#include "stdafx.h"
#include "UpdaterCtl.h"

STDMETHODIMP CUpdaterCtl::GetInterfaceSafetyOptions(REFIID riid,
                                                    DWORD* pdwSupportedOptions,
                                                    DWORD* pdwEnabledOptions)
{
    if (pdwSupportedOptions == NULL || pdwEnabledOptions == NULL)
        return E_POINTER;

~>    *pdwSupportedOptions =INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA;
~>    *pdwEnabledOptions = INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA;
    return S_OK;
}

STDMETHODIMP CUpdaterCtl::DownloadAndRun(BSTR url)
{
    return LaunchInstaller(url);
}
