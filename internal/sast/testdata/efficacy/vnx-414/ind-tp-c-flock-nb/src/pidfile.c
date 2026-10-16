#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

int write_pidfile(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0)
        return -1;
~>    flock(fd, LOCK_EX | LOCK_NB);
    ftruncate(fd, 0);
    dprintf(fd, "%d\n", (int)getpid());
    return fd;
}

void refresh_stats(pthread_mutex_t *m, struct stats *s)
{
~>    pthread_mutex_trylock(m);
    s->refreshes++;
    pthread_mutex_unlock(m);
}
