#include <unistd.h>

void shutdown_conn(int fd) {
    flush_pending(fd);
    close(fd);
    stats.closed++;
~>    close(fd);
}
