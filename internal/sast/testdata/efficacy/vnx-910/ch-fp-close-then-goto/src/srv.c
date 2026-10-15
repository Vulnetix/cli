#include <sys/socket.h>
#include <unistd.h>

int serve_one(int lfd)
{
    int c = accept(lfd, NULL, NULL);
    if (c < 0)
        return -1;
    if (send(c, "hi", 2, 0) < 0) {
        close(c);
        goto fail;
    }
    send(c, "bye", 3, 0);
    close(c);
    return 0;
fail:
    return -1;
}
