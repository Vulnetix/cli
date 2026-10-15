#include <unistd.h>

int enter(const char *dir)
{
    if (chroot(dir) != 0 || chdir("/") != 0)
        return -1;
    return 0;
}
