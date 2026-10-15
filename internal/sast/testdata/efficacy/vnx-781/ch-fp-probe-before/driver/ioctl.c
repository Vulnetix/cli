#include <ntddk.h>

NTSTATUS HandleNeither(PIRP Irp, PIO_STACK_LOCATION stack)
{
    UCHAR local[64];
    ULONG len = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID user = stack->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@;
    __try {
        ProbeForRead(user, len, sizeof(UCHAR));
        RtlCopyMemory(local, user, min(len, sizeof(local)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}
