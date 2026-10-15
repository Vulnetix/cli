#include <ntddk.h>

#define IOCTL_ACME_SET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)

NTSTATUS SetConfig(PIRP Irp, PIO_STACK_LOCATION stack)
{
    PVOID in = stack->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@;
    ULONG len = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID out = Irp->UserBuffer;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ACME_CONFIG local;

    if (Irp->RequestorMode == KernelMode) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    __try {
        ProbeForRead(in, len, sizeof(UCHAR));
        ProbeForWrite(out, outLen, sizeof(UCHAR));
        RtlCopyMemory(&local, in, min(len, sizeof(local)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}
