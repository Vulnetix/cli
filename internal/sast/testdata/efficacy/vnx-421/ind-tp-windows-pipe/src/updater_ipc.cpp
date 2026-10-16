#include <windows.h>

HANDLE CreateUpdaterPipe()
{
~>    return CreateNamedPipeW(L"\\\\.\\pipe\\AcmeUpdater",
                            PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
}
