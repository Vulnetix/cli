#include <unistd.h>

int confine(const char *jail)
{
    chdir("/var/empty");
~>    if (chroot(jail) < 0)
        return -1;
    return setuid(65534);
}
