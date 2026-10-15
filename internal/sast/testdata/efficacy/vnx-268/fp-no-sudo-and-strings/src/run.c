#include <stdio.h>
#include <stdlib.h>

int build(const char *target)
{
    char cmd[128];
    fprintf(stderr, "try 'sudo sysctl -w net.inet.tcp.msl=%d'\n", 1000);
    snprintf(cmd, sizeof(cmd), "make %s", target);
    return system(cmd);
}
