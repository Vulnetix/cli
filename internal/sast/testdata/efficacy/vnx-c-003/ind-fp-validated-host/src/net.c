#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int is_valid_hostname(const char *host);

int traceroute(const char *host)
{
    char cmd[256];
    if (!is_valid_hostname(host))
        return -1;
    snprintf(cmd, sizeof(cmd), "traceroute -n %s", host);
    return system(cmd);
}

int lookup(const char *name)
{
    char cmd[256];
    if (strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(name))
        return -1;
    snprintf(cmd, sizeof(cmd), "host %s", name);
    return system(cmd);
}
