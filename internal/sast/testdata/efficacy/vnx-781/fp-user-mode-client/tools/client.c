#include <windows.h>
#include <winioctl.h>

#define IOCTL_ACME_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_ACCESS)

int main(void)
{
    HANDLE h = CreateFileW(L"\\\\.\\Acme", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    ULONG value = 0;
    DWORD got = 0;
    DeviceIoControl(h, IOCTL_ACME_QUERY, NULL, 0, &value, sizeof(value), &got, NULL);
    CloseHandle(h);
    return 0;
}
