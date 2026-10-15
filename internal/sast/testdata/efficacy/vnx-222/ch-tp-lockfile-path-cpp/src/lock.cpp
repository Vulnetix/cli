#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

int acquire_lock(const char *run_dir, const char *service)
{
    char lock_path[64];
~>    std::snprintf(lock_path,
                  sizeof(lock_path),
                  "%s/%s.lock", run_dir, service);
    int fd = ::open(lock_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    return fd;
}
