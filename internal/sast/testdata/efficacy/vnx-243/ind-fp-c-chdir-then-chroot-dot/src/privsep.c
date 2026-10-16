#include <unistd.h>

int enter(const char *dir)
{
    if (chdir(dir) == -1)
        return -1;
    if (chroot(".") == -1)
        return -1;
    return 0;
}

int enter_same(const char *dir)
{
    if (chdir(dir) == -1)
        return -1;
    if (chroot(dir) == -1)
        return -1;
    return 0;
}
