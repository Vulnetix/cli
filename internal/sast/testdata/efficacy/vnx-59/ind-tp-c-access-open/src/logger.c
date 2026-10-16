#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int open_log(const char *path)
{
~>    if (access(path, W_OK) == 0) {
        return open(path, O_WRONLY | O_APPEND);
    }
    return -1;
}

int write_pid(void)
{
~>    int fd = open("/tmp/appd.pid", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    dprintf(fd, "%d\n", getpid());
    close(fd);
~>    chmod("/tmp/appd.sock", 0777);
    return 0;
}
