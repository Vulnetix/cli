#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>

int open_status(pid_t pid)
{
    char path[64];

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    return open(path, O_RDONLY);
}
