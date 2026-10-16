#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *lock_path = "/var/tmp/backupd.lock";

int acquire_lock(void)
{
    int fd;

~>    fd = open(lock_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    return fd;
}

int write_pidfile(void)
{
~>    int fd = creat("/dev/shm/backupd.pid", S_IRUSR | S_IWUSR | S_IROTH);
    return fd;
}

int open_socket_marker(void)
{
~>    return open("/tmp/backupd.marker",
                O_RDWR | O_CREAT,
                S_IRWXU | S_IRWXO);
}
