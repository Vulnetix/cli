#include <string.h>
#include <unistd.h>

void run_tool(const char *arg)
{
    char cmd[128] = "/usr/bin/convert ";

~>    strncat(cmd, arg, sizeof(cmd) - strlen(cmd) - 1);
    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
}
