#include <sys/socket.h>
#include <netinet/in.h>

struct conn {
    int fd;
};

void init(void)
{
    struct conn c;
    struct conn *p = &c;
    struct sockaddr_storage ss;
    int fd = 0;
    int *ip = &fd;
    void *v = (void *)&fd;
    connect(fd, (struct sockaddr *)&ss, sizeof ss);
    (void)p; (void)ip; (void)v;
}
