#include <unistd.h>

int enter_jail(const char *dir) {
    if (chroot(dir) != 0)
        return -1;
    if (chdir("/") != 0)
        return -1;
    return setuid(65534);
}
