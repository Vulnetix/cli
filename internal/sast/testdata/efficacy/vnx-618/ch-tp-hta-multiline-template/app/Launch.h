#pragma once
class ATL_NO_VTABLE CLaunch :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CLaunch, &CLSID_Launch>,
~>	public IObjectSafetyImpl<CLaunch,
		INTERFACESAFE_FOR_UNTRUSTED_CALLER |
		INTERFACESAFE_FOR_UNTRUSTED_DATA>,
	public IDispatchImpl<ILaunch, &IID_ILaunch>
{
};
