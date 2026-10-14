#include <stdio.h>
#include <stdlib.h>

int ping_host(const char *host)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /dev/null", host);
~>    return system(cmd);
}

int convert(const char *user_filename, int quality)
{
    char cmd[512];

    sprintf(cmd, "convert -quality %d %s out.png", quality, user_filename);
~>    if (system(cmd) != 0)
        return -1;
    return 0;
}
