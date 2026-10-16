#include <windows.h>

HANDLE create_service_pipe(void)
{
    return CreateNamedPipeA("\\\\.\\pipe\\AcmeService",
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE | PIPE_WAIT,
                            1, 4096, 4096, 0, NULL);
}
