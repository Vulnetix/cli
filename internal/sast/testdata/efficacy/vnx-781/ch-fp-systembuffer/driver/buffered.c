#include <ntddk.h>

NTSTATUS Buffered(PIRP Irp)
{
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    /* METHOD_NEITHER would use Type3InputBuffer; this one is METHOD_BUFFERED */
    RtlZeroMemory(buf, 16);
    return STATUS_SUCCESS;
}
