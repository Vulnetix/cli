#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void enter_jail(const char *jail, uid_t uid)
{
~>    if (chroot(jail) != 0) {
        perror("chroot");
        exit(1);
    }
    if (setuid(uid) != 0) {
        perror("setuid");
        exit(1);
    }
    execl("/bin/worker", "worker", (char *)NULL);
}
