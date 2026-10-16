#include <stdlib.h>
#include <string.h>

int run_listing(const char *dir)
{
    char cmd[512];

~>    strcat(cmd, "ls -l ");
    strncat(cmd, dir, sizeof cmd - 8);
    return system(cmd);
}
