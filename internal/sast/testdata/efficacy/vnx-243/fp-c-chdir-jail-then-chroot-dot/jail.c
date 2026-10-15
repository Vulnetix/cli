#include <unistd.h>

int enter_jail(const char *dir) {
    if (chdir(dir) != 0)
        return -1;
    if (chroot(".") != 0)
        return -1;
    return 0;
}

int enter_same(const char *root) {
    chdir(root);
    chroot(root);
    return 0;
}
