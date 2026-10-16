#include <unistd.h>

int setup(const char *jail)
{
~>    if (chroot(jail) != 0)
        return -1;
    if (chdir("work") != 0)
        return -1;
    return 0;
}
