#include <fcntl.h>
#include <unistd.h>

int read_score(void)
{
    char buf[32];
    int fd = open("/proc/self/oom_score_adj", O_RDONLY);
    if (fd == -1)
        return -1;
    if (read(fd, buf, sizeof(buf)) <= 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return atoi(buf);
}

void devnull(void)
{
    int fd;
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        if (fd > 2) close(fd);
    }
}

void spawn(char **argv)
{
    execv(argv[0], argv);
}
