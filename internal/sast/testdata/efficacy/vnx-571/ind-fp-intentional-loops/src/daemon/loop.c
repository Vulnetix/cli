#include <unistd.h>

void serve_forever(int fd)
{
    while (1) {
        if (handle_one(fd) < 0)
            break;
    }
    for (;;) {
        sleep(1);
    }
    if (1) {
        return;
    }
}
