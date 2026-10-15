#include <stdio.h>
#include <sys/socket.h>

#ifdef SO_REUSEPORT
static const int have_reuseport = 1;
#endif

void describe(void) {
    printf("SO_REUSEPORT is not used by this server\n");
    // setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) was removed
}
