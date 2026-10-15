#include <ntddk.h>
#include <wdf.h>

VOID EvtIoInCallerContext(WDFDEVICE Device, WDFREQUEST Request)
{
    PVOID buf;
    size_t len;
    WDFMEMORY mem;
    NTSTATUS status = WdfRequestRetrieveUnsafeUserInputBuffer(Request, 0, &buf, &len);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    status = WdfRequestProbeAndLockUserBufferForRead(Request, buf, len, &mem);
    WdfDeviceEnqueueRequest(Device, Request);
}
