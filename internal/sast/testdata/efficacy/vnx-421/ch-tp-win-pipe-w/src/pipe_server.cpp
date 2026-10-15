#include <windows.h>

HANDLE open_pipe() {
~>    HANDLE h = CreateNamedPipeW(
        L"\\\\.\\pipe\\updater",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
    return h;
}
