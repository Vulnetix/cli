#include <stdio.h>
#include <stdlib.h>

int add_user(const char *name)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo /usr/sbin/useradd -m %s", name);
~>    return system(cmd);
}

FILE *tail_log(const char *file)
{
    char buf[512];
    sprintf(buf, "sudo tail -n 100 %s", file);
~>    return popen(buf, "r");
}
