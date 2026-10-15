#include "Viewer.h"

STDMETHODIMP CViewer::SetInterfaceSafetyOptions(REFIID riid, DWORD dwOptionSetMask, DWORD dwEnabledOptions)
{
	if ((dwEnabledOptions & INTERFACESAFE_FOR_UNTRUSTED_CALLER) != 0)
		return E_FAIL;
	if (dwOptionSetMask & ~INTERFACESAFE_FOR_UNTRUSTED_DATA)
		return E_FAIL;
	return S_OK;
}

STDMETHODIMP CViewer::GetInterfaceSafetyOptions(REFIID riid, DWORD *pdwSupported, DWORD *pdwEnabled)
{
	*pdwSupported = 0;
	*pdwEnabled = 0;
	return E_NOTIMPL;
}

bool CViewer::IsSafe(DWORD opts)
{
	return (opts & INTERFACESAFE_FOR_UNTRUSTED_CALLER) == INTERFACESAFE_FOR_UNTRUSTED_CALLER;
}
