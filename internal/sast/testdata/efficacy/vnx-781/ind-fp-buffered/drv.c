#include <ntddk.h>

NTSTATUS Handle(PIRP Irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PVOID in = Irp->AssociatedIrp.SystemBuffer;
    ULONG len = sp->Parameters.DeviceIoControl.InputBufferLength;
    RtlCopyMemory(g_buf, in, len);
    return STATUS_SUCCESS;
}
