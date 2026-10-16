#pragma once
#include "resource.h"
#include <atlctl.h>

class ATL_NO_VTABLE CLauncherCtl :
    public CComObjectRootEx<CComSingleThreadModel>,
    public IDispatchImpl<ILauncherCtl, &IID_ILauncherCtl, &LIBID_LauncherLib, 1, 0>,
    public CComControl<CLauncherCtl>,
~>    public IObjectSafetyImpl<CLauncherCtl, INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA>,
    public CComCoClass<CLauncherCtl, &CLSID_LauncherCtl>
{
public:
    DECLARE_REGISTRY_RESOURCEID(IDR_LAUNCHERCTL)

    BEGIN_CATEGORY_MAP(CLauncherCtl)
~>        IMPLEMENTED_CATEGORY(CATID_SafeForScripting)
~>        IMPLEMENTED_CATEGORY(CATID_SafeForInitializing)
    END_CATEGORY_MAP()

    STDMETHOD(Run)(BSTR commandLine, LONG* exitCode);
};
