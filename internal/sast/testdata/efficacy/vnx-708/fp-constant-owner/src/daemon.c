#include <unistd.h>
#include <stdlib.h>

#define RUN_UID 990
#define RUN_GID 990

int prepare(int argc, char **argv) {
    const char *name = argv[0];
    (void)name;
    if (chown("/var/run/mydaemon.pid", RUN_UID, RUN_GID) != 0)
        return -1;
    if (fchown(3, getuid(), getgid()) != 0)
        return -1;
    return 0;
}
