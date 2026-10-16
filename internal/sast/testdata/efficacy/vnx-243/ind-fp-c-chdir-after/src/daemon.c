#include <unistd.h>

int drop(const char *dir)
{
    if (chroot(dir) != 0 || chdir("/") != 0)
        return -1;
    return setuid(65534);
}
