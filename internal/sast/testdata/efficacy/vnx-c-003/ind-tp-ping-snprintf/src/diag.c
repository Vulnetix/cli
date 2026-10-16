#include <stdio.h>
#include <stdlib.h>

int diag_ping(const char *host)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2 %s > /dev/null 2>&1", host);
~>    return system(cmd);
}
