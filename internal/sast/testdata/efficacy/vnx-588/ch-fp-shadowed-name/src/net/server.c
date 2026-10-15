#include <sys/socket.h>
#include <netinet/in.h>

static int count_peers(void)
{
    int addr = 0;
    return addr;
}

static void bind_any(int fd)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    bind(fd, (struct sockaddr *)&addr, sizeof addr);
}
