#include <windows.h>

HANDLE first_instance(void)
{
    return CreateNamedPipeA("\\\\.\\pipe\\svc-control",
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                            1, 4096, 4096, 0, NULL);
}

HANDLE next_instance(void)
{
    return CreateNamedPipeA("\\\\.\\pipe\\svc-control", PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_BYTE, 4, 4096, 4096, 0, NULL);
}
