#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int open_control(void)
{
~>    if (mkfifo("/tmp/backupd.fifo", 0600) < 0)
        perror("mkfifo");
    return 0;
}

int listen_control(void)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
~>    strncpy(addr.sun_path, "/tmp/backupd.sock", sizeof(addr.sun_path) - 1);
    unlink(addr.sun_path);
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

int listen_pid(void)
{
    struct sockaddr_un sa;
    sa.sun_family = AF_UNIX;
~>    snprintf(sa.sun_path, sizeof(sa.sun_path), "/var/tmp/worker-%d.sock", (int)getpid());
    return 0;
}
