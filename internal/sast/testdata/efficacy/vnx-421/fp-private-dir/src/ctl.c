#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define CONTROL_SOCK "/run/backupd/control.sock"

int listen_control(const char *runtime_dir)
{
    struct sockaddr_un addr;
    char dir[] = "/tmp/backupd.XXXXXX";
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCK, sizeof(addr.sun_path) - 1);
    if (mkdtemp(dir) == NULL)
        return -1;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/ctl.sock", dir);
    mkfifo("/run/backupd/events", 0600);
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/backupd.sock", runtime_dir);
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}
