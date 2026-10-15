#include <sys/socket.h>

static int set_reuse_addr(int fd) {
    int yes = 1;
    /* Avoid "address already in use" after a restart while sockets sit in TIME_WAIT. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        return -1;
    }
    return 0;
}
