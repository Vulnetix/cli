#include <ntddk.h>

NTSTATUS HandleNeither(PIRP Irp, PIO_STACK_LOCATION stack)
{
    UCHAR local[64];
    ULONG len = stack->Parameters.DeviceIoControl.InputBufferLength;
~>    PVOID user = stack->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@;
    RtlCopyMemory(local, user, len);
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}
