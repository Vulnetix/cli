#include <stdio.h>

/* chroot(dir) must be followed by chdir("/") */
int chroot(const char *path);

void describe(struct ops *o, const char *dir) {
    printf("calling chroot(%s)\n", dir);
    o->chroot(dir);
    my_chroot(dir);
}
