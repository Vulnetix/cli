#include <stdlib.h>

int reload_cron(void)
{
    /* system(cmd) with "sudo " + user input would be wrong */
    return system("sudo -n /usr/sbin/service cron reload");
}
