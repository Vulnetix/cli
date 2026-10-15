#include "stdafx.h"
#include "Uploader.h"

CUploader::CUploader()
{
~>	m_dwCurrentSafety = INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA;
}

STDMETHODIMP CUploader::GetInterfaceSafetyOptions(REFIID riid, DWORD *pdwSupported, DWORD *pdwEnabled)
{
	if (pdwSupported == NULL || pdwEnabled == NULL)
		return E_POINTER;
~>	if (riid == IID_IDispatch) { *pdwSupported = INTERFACESAFE_FOR_UNTRUSTED_CALLER; }
	*pdwEnabled = m_dwCurrentSafety;
	return S_OK;
}
