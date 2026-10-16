#include <stdio.h>
#include <stdlib.h>

#define RELOAD_CMD "systemctl reload nginx"

void sysinfo(int verbose)
{
    char cmd[64];
    FILE *fp;

    if (system(NULL) == 0)
        return;
    system("date");
    system(RELOAD_CMD);
    fp = popen("uname -r", "r");
    if (fp)
        pclose(fp);
    snprintf(cmd, sizeof(cmd), "dmesg | tail -n %d", verbose ? 50 : 10);
    system(cmd);
    /* system(user_input) is forbidden in this module */
}
