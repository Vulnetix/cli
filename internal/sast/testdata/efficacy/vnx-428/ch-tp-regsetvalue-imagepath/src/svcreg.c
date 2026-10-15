#include <windows.h>

LONG register_image(HKEY svc)
{
    static const wchar_t img[] = L"C:\\Program Files\\Acme Backup\\backupd.exe";
~>    return RegSetValueExW(svc, L"ImagePath", 0, REG_EXPAND_SZ,
                          (const BYTE *)L"C:\\Program Files\\Acme Backup\\backupd.exe -service",
                          sizeof(img));
}
