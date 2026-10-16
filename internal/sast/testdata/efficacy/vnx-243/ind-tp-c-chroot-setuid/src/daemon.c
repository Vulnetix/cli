#include <stdio.h>
#include <unistd.h>

int drop_privileges(const char *jail)
{
~>    if (chroot(jail) == -1) {
        perror("chroot");
        return -1;
    }
    if (setgid(65534) != 0 || setuid(65534) != 0)
        return -1;
    return 0;
}
