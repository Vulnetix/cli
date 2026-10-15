#include <wdm.h>

#define IOCTL_COPY_IN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)

NTSTATUS CopyIn(PIO_STACK_LOCATION irpSp, PVOID dest, SIZE_T destLen)
{
    PVOID userIn;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

~>    userIn = irpSp->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@;
    if (inLen > destLen) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(dest, userIn, inLen);
    return STATUS_SUCCESS;
}
