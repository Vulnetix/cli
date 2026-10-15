#include <fcntl.h>
#include <spawn.h>

bool Worker::start(const char *dir)
{
~>    lock_fd_ = ::openat(dirfd_, "worker.lock", O_RDWR | O_CREAT, 0644);
    if (lock_fd_ < 0)
        return false;
    pid_t pid;
    return posix_spawnp(&pid, "helper", nullptr, nullptr, argv_, environ) == 0;
}
