#include <ntddk.h>

#define IOCTL_ACME_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_ACCESS)

NTSTATUS HandleQuery(PIRP Irp, PIO_STACK_LOCATION stack)
{
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
~>    PULONG out = (PULONG)Irp->UserBuffer;
    if (outLen < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *out = g_Counter;
    Irp->IoStatus.Information = sizeof(ULONG);
    return STATUS_SUCCESS;
}
