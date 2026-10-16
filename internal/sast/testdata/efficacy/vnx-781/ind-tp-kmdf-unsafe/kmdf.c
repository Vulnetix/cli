#include <wdf.h>

VOID EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutLen, size_t InLen, ULONG Code) {
    PVOID buf;
~>    NTSTATUS st = WdfRequestRetrieveUnsafeUserInputBuffer(Request, 16, &buf, NULL);
    if (NT_SUCCESS(st)) {
        *(volatile UCHAR *)buf = 0;
    }
    WdfRequestComplete(Request, st);
}
