#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

int ipc_connect(int fd, const char *sock_path)
{
    struct sockaddr_un addr;

    if (strlen(sock_path) >= sizeof(addr.sun_path))
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    return connect(fd, (struct sockaddr *)&addr, sizeof(addr));
}

int open_cfg(const char *name)
{
    char path[256];

    if (strlen(name) + sizeof("/etc/app/") > sizeof(path))
        return -1;
    strcpy(path, "/etc/app/");
    strncat(path, name, sizeof(path) - strlen(path) - 1);
    return open(path, 0);
}
