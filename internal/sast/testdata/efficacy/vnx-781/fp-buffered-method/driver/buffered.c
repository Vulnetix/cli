#include <ntddk.h>

#define IOCTL_ACME_GET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS Get(PIRP Irp, PIO_STACK_LOCATION stack)
{
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PMDL mdl = Irp->MdlAddress;
    if (len < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *(PULONG)buf = 7;
    return STATUS_SUCCESS;
}
