#include <stdio.h>
#include <unistd.h>

void run_hook(const char *script, const char *arg)
{
    char cmd[512];

    snprintf(cmd, sizeof cmd, "%s %s", script, arg);
    if (fork() == 0) {
~>        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
}
