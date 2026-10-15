#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

int start_worker(void)
{
    int sv[2];
    uint32_t cmd = 1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;
    write(sv[0], &cmd, sizeof(cmd));
    return sv[1];
}
