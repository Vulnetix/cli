#include <unistd.h>

int my_chroot(const char *p);

int run(struct ops *o, const char *p)
{
    o->chroot(p);
    my_chroot(p);
    /* chroot(p) must be followed by chdir("/") */
    puts("call chroot() then chdir()");
    return 0;
}
