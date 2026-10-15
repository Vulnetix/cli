#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

void write_pid(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT, 0644);
~>  flock(fd, LOCK_EX | LOCK_NB);
    ftruncate(fd, 0);
    dprintf(fd, "%d\n", getpid());
}

void append_journal(int fd, struct flock *fl)
{
~>  lockf(fd, F_TLOCK, 0);
    write(fd, "x", 1);
~>  fcntl(fd, F_SETLK, fl);
    write(fd, "y", 1);
}
