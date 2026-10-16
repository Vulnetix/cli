#include <windows.h>

BOOL Send(HANDLE h, void *p, DWORD n) {
    DWORD ret = 0;
    // The driver reads Type3InputBuffer only after probing
    return DeviceIoControl(h, 0x222003, p, n, NULL, 0, &ret, NULL);
}
