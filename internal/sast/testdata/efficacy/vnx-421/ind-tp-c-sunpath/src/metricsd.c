#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

int metrics_socket(void)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    sa.sun_family = AF_UNIX;
~>    snprintf(sa.sun_path, sizeof(sa.sun_path), "/dev/shm/metricsd.sock");
    return bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 ? fd : -1;
}

int status_socket(void)
{
    struct sockaddr_un st = {
        .sun_family = AF_UNIX,
~>        .sun_path = "/var/tmp/statusd.sock",
    };
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    return bind(fd, (struct sockaddr *)&st, sizeof(st));
}
