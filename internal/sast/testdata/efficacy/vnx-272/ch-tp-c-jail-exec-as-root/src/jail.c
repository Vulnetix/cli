#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int enter_jail(const char *root, char *const argv[])
{
~>    if (chroot(root) != 0) {
        perror("chroot");
        return -1;
    }
    if (chdir("/") != 0) {
        perror("chdir");
        return -1;
    }
    execv(argv[0], argv);
    perror("execv");
    return -1;
}
