#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

struct frame {
    unsigned char kind;
    unsigned char body[63];
};

int open_listener(int port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -1;
    }
    return fd;
}

int frame_kind(void *data)
{
    char buf[64];
    struct frame *a = (struct frame *)buf;
    struct frame *b = (struct frame *)&buf[0];
    struct frame *c = (struct frame *)data;
    return a->kind + b->kind + c->kind;
}
