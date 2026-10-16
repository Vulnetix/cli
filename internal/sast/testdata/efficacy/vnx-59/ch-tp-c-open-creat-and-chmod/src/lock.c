#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int take_lock(void)
{
    int fd = open("/tmp/daemon.lock", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    write(fd, "1", 1);
    return fd;
}

void publish(void)
{
~>    chmod("/var/tmp/daemon.status", 0666);
}
