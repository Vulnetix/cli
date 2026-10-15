#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

int fetch_banner(int sock, char *buf, size_t len)
{
    ssize_t n;

    send(sock, "HELO\r\n", 6, 0);
~>    close(sock);
    fprintf(stderr, "request sent\n");
    n = recv(sock, buf, len - 1, 0);
    if (n < 0) {
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

struct conn {
    int fd;
};

void conn_finish(struct conn *c, const char *msg, size_t len)
{
~>    close(c->fd);
    write(c->fd, msg, len);
}
