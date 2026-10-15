#include <windows.h>
#include <sys/un.h>
#include <cstring>

#define CONTROL_SOCK "/dev/shm/render.sock"
static const char FIFO_PATH[] = "/tmp/render.fifo";

void make_channels(struct sockaddr_un &addr)
{
~>    std::strcpy(addr.sun_path, CONTROL_SOCK);
~>    mkfifo(FIFO_PATH, 0660);
}

HANDLE make_pipe()
{
~>    return CreateNamedPipeW(L"\\\\.\\pipe\\render-control",
                            PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_MESSAGE | PIPE_WAIT,
                            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
}
