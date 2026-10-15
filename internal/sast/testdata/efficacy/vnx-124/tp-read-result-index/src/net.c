#include <unistd.h>
#include <sys/socket.h>

void handle(int fd)
{
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
~>    buf[n] = '\0';
    process(buf);
}

void link_target(const char *path)
{
    char target[256];
    ssize_t len = readlink(path, target, sizeof(target) - 1);
~>    target[len] = 0;
    puts(target);
}

void sock(int s)
{
    char msg[128];
    int got;
    got = recv(s, msg, sizeof msg - 1, 0);
~>    msg[got - 1] = '\0';
}
