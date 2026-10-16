#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Make sure the lock file belongs to whoever is running us, even if a
 * previous root run created it. */
int reclaim_lock(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *lock = "/run/app/app.lock";
    if (chown(lock, getuid(), getgid()) != 0) {
        perror("chown");
        return -1;
    }
    int fd = open(lock, O_RDWR);
    if (fd >= 0) {
        fchown(fd, geteuid(), getegid());
        close(fd);
    }
    return 0;
}
