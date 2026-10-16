#include <ntddk.h>

NTSTATUS Handle(PIRP Irp) {
    PVOID p = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(p, 8);
    return STATUS_SUCCESS;
}
