#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>

void setup(struct sockaddr_un *addr)
{
    mkdir("/run/backupd", 0700);
    strncpy(addr->sun_path, "/run/backupd/control.sock", sizeof(addr->sun_path) - 1);
    mkfifo("/run/backupd/events", 0600);
}
