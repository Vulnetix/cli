#pragma once
#include <atlctl.h>

class ATL_NO_VTABLE CFileTool :
    public CComObjectRootEx<CComSingleThreadModel>,
    public CComCoClass<CFileTool, &CLSID_FileTool>,
~>    public IObjectSafetyImpl<CFileTool, INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA>,
    public IDispatchImpl<IFileTool, &IID_IFileTool, &LIBID_FileToolLib>
{
public:
    STDMETHOD(DeleteFile)(BSTR path);
    STDMETHOD(RunProgram)(BSTR cmd);
};
