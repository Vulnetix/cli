#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int open_lock(void)
{
~>    int fd = open("/tmp/agent.lock", O_RDWR | O_CREAT, 0666);
    return fd;
}

int open_report(void)
{
    const char *path = "/var/tmp/report.dat";
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC,
                  S_IRWXU | S_IRWXG | S_IRWXO);
    return fd;
}

int open_pid(void)
{
~>    return creat("/tmp/daemon.pid", 0644);
}
