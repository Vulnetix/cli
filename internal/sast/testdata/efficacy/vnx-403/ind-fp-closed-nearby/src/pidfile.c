#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int write_pidfile(const char *path)
{
    char buf[32];
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    int n = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (write(fd, buf, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int restart_self(char *const argv[])
{
    if (write_pidfile("/run/app.pid") < 0)
        return -1;
    execv("/proc/self/exe", argv);
    return -1;
}
