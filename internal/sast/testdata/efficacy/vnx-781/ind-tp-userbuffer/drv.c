#include <ntddk.h>

NTSTATUS Handle(PIRP Irp) {
~>    PUCHAR out = (PUCHAR)Irp->UserBuffer;
    out[0] = 1;
    return STATUS_SUCCESS;
}
