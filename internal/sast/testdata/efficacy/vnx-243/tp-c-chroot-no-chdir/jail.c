#include <unistd.h>
#include <stdio.h>

int enter_jail(const char *dir) {
~>    if (chroot(dir) != 0) {
        perror("chroot");
        return -1;
    }
    setuid(65534);
    return 0;
}
