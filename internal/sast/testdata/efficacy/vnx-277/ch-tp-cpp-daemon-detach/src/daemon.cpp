#include <sys/stat.h>
#include <unistd.h>

#include "daemon.h"

void Daemon::detach()
{
    if (fork() > 0)
        _exit(0);
    setsid();
~>    ::umask(0);
    if (chdir("/") != 0)
        _exit(1);
}
