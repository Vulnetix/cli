#include <ntddk.h>

NTSTATUS DispatchIoctl(PDEVICE_OBJECT Dev, PIRP Irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG len = sp->Parameters.DeviceIoControl.InputBufferLength;
~>    PVOID in = sp->Parameters.DeviceIoControl.Type3InputBuffer;
    RtlCopyMemory(g_buf, in, len);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}
