#include <unistd.h>

int serve(int fd)
{
    char req[1024];
    ssize_t got = read(fd, req, sizeof(req));
    if (got < 0)
        return -1;
~>    req[got] = '\0';
    return 0;
}
