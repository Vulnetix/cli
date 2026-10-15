#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void drop(uid_t uid, gid_t gid, const char *jail)
{
    if (chroot(jail) != 0 || chdir("/") != 0) {
        perror("chroot");
        exit(1);
    }
    if (setgid(gid) == -1)
        exit(1);
    int rc = setuid(uid);
    if (rc != 0)
        abort();
}
