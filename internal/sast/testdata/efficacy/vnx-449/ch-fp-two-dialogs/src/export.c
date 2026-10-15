#include <windows.h>

void Export(HWND h, BOOL done)
{
    if (done) {
        MessageBox(h, TEXT("Export finished"), TEXT("Export"), MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (MessageBox(h, TEXT("Export failed. Retry?"), TEXT("Export"), MB_RETRYCANCEL) == IDRETRY) {
        Export(h, TRUE);
    }
}
