#include <stdlib.h>
#include <unistd.h>

int reboot_host(void)
{
    /* system("sudo " + cmd) would be unsafe */
    return system("sudo /sbin/reboot");
}

int whoami(void)
{
    return execlp("sudo", "sudo", "-n", "/usr/bin/id", (char *)NULL);
}
