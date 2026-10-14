#include <stdio.h>
#include <stdlib.h>

#define BASE_DIR "/var/cache/app"
#define CLEAR_CMD "clear"

void maintenance(int pid, int level)
{
    char cmd[128];
    const char *uptime = "uptime";
    FILE *p;

    system("clear");
    system(CLEAR_CMD);
    p = popen("uname -r", "r");
    pclose(p);
    system(uptime);
    if (system(NULL) == 0)
        return;

    snprintf(cmd, sizeof(cmd), "kill -HUP %d", pid);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "rm -rf %s/level-%d", BASE_DIR, level);
    system(cmd);

    strcpy(cmd, "sync");
    strcat(cmd, " && echo done");
    system(cmd);
}
