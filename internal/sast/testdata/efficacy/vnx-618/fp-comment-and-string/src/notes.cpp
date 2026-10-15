// Do not derive from IObjectSafetyImpl<CX, INTERFACESAFE_FOR_UNTRUSTED_CALLER>: the control runs commands.
/* IMPLEMENTED_CATEGORY(CATID_SafeForScripting) was removed in 2.1 */
const char *kHelp = "new ActiveXObject(\"WScript.Shell\") is blocked by policy";
STDMETHODIMP CSafe::GetInterfaceSafetyOptions(REFIID riid, DWORD *pdwSupportedOptions, DWORD *pdwEnabledOptions)
{
    *pdwSupportedOptions = 0;
    *pdwEnabledOptions = 0;
    return E_NOINTERFACE;
}
