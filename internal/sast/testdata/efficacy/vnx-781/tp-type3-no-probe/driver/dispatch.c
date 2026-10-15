#include <ntddk.h>

#define IOCTL_ACME_SET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _ACME_CONFIG {
    ULONG Mode;
    ULONG Length;
} ACME_CONFIG, *PACME_CONFIG;

NTSTATUS AcmeDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ACME_SET_CONFIG: {
~>        PACME_CONFIG cfg = (PACME_CONFIG)stack->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@;
        g_Mode = cfg->Mode;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
