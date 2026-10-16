#include <windows.h>

HMODULE load_bcrypt(void)
{
    return LoadLibraryExW(L"bcrypt.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

HMODULE load_vendor_plugin(void)
{
    return LoadLibraryW(L"C:\\Program Files\\Acme\\plugins\\acme_hsm.dll");
}

HMODULE load_icons(void)
{
    return LoadLibraryExW(L"acme_icons.dll", NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
}
