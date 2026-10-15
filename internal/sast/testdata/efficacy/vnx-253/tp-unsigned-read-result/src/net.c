#include <unistd.h>
#include <sys/socket.h>

int pump(int fd, char *buf, size_t cap)
{
    size_t n = read(fd, buf, cap);
~>    if (n < 0)
        return -1;
    unsigned int sent = send(fd, buf, n, 0);
~>    if (sent < 0) {
        perror("send");
    }
    return 0;
}
