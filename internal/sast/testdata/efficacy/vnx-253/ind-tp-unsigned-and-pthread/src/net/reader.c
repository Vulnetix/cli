#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include "reader.h"

int reader_pump(int fd, char *buf, size_t cap)
{
    size_t n = read(fd, buf, cap);
~>    if (n < 0)
        return -1;
    unsigned int got = recv(fd, buf, cap, 0);
~>    if (got < 0)
        return -1;
    return (int)(n + got);
}

int reader_start(struct reader *r)
{
~>    if (pthread_create(&r->thread, NULL, reader_main, r) == -1)
        return -1;
    int rc = pthread_mutex_lock(&r->lock);
~>    if (rc < 0)
        return -1;
    pthread_mutex_unlock(&r->lock);
    return 0;
}
