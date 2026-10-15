#include <sys/socket.h>
#include <unistd.h>

int probe(struct conn *c, const struct sockaddr *addr, socklen_t len)
{
    c->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (c->sock < 0)
        return -1;
    int ok = connect(c->sock, addr, len) == 0;
    close(c->sock);
    return ok;
}

void restart(char **argv)
{
    execvp(argv[0], argv);
}
