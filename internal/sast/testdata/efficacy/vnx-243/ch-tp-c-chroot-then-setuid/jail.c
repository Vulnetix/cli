#include <unistd.h>

int enter_jail(const char *dir, uid_t uid) {
~>    if (chroot(dir) != 0)
        return -1;
    if (setuid(uid) != 0)
        return -1;
    return 0;
}
