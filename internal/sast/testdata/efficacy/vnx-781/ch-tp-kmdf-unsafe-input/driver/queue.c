#include <ntddk.h>
#include <wdf.h>

VOID EvtIoInCallerContext(WDFDEVICE Device, WDFREQUEST Request)
{
    PVOID buf;
    size_t len;
~>    NTSTATUS status = WdfRequestRetrieveUnsafeUserInputBuffer(Request, 0, &buf, &len);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    RtlCopyMemory(&g_state, buf, sizeof(g_state));
}
