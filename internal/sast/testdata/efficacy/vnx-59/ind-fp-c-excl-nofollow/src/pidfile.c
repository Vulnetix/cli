#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int write_pid(void)
{
    int fd = open("/tmp/appd.pid", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    dprintf(fd, "%d\n", getpid());
    return close(fd);
}

int scratch(void)
{
    char tmpl[] = "/tmp/appd.XXXXXX";
    int fd = mkstemp(tmpl);
    return fd;
}
