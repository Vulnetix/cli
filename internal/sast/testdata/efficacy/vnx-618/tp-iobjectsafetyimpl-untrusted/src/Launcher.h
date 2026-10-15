#pragma once
#include "resource.h"

class ATL_NO_VTABLE CLauncher :
    public CComObjectRootEx<CComSingleThreadModel>,
    public CComCoClass<CLauncher, &CLSID_Launcher>,
~>    public IObjectSafetyImpl<CLauncher, INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA>,
    public IDispatchImpl<ILauncher, &IID_ILauncher, &LIBID_LauncherLib>
{
public:
    STDMETHOD(RunCommand)(BSTR cmdLine);
    STDMETHOD(WriteFile)(BSTR path, BSTR data);
};

class ATL_NO_VTABLE CUpdater :
~>    public IObjectSafetyImpl<CUpdater,
                             INTERFACESAFE_FOR_UNTRUSTED_CALLER>,
    public IDispatchImpl<IUpdater, &IID_IUpdater, &LIBID_LauncherLib>
{
};
