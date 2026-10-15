#include <ntddk.h>

NTSTATUS Lock(PIRP Irp, ULONG len)
{
    PMDL mdl = IoAllocateMdl(Irp->UserBuffer, len, FALSE, FALSE, NULL);
    __try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_SUCCESS;
}
