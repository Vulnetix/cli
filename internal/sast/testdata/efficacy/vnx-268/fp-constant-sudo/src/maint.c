#include <stdlib.h>
#include <unistd.h>

int reload(void)
{
    execlp("sudo", "sudo", "-n", "/usr/sbin/nginx", "-s", "reload", (char *)NULL);
    return system("sudo /usr/sbin/service cron restart");
}
