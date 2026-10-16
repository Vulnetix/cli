#include <ntddk.h>

NTSTATUS DispatchIoctl(PDEVICE_OBJECT Dev, PIRP Irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PVOID in = sp->Parameters.DeviceIoControl.Type3InputBuffer;
    ULONG len = sp->Parameters.DeviceIoControl.InputBufferLength;
    __try {
        ProbeForRead(in, len, sizeof(UCHAR));
        RtlCopyMemory(g_buf, in, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}
