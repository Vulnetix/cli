#include <ntddk.h>

NTSTATUS DispatchQuery(PDEVICE_OBJECT, PIRP irp)
{
~>    ULONG *out = static_cast<ULONG *>(irp->UserBuffer);
    *out = 42;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
