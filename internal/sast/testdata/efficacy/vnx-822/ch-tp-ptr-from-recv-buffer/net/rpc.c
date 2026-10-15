#include <sys/socket.h>
#include <stdint.h>

typedef void (*handler_fn)(void *);

int serve_once(int fd)
{
    unsigned char msg[64];
    ssize_t n = recvfrom(fd, msg, sizeof(msg), 0, NULL, NULL);
    if (n < 16)
        return -1;
~>    handler_fn cb = *(handler_fn **)(msg + 8);
~>    char *ctx = (char *)strtoull((const char *)msg + 16, NULL, 16);
    (void)ctx;
    (void)cb;
    return 0;
}
