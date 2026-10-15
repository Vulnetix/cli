#include <spawn.h>
#include <cstdlib>
#include <unistd.h>

int fire_hook(uid_t uid, const char *hook)
{
    if (seteuid(uid) == -1) {
        return -1;
    }
    int rc = 0;
~>    rc = std::system(hook);
    return rc;
}

int spawn_hook(uid_t uid, char *const argv[], char *const envp[])
{
    pid_t pid;
    seteuid(uid);
~>    return posix_spawnp(&pid, argv[0], nullptr, nullptr, argv, envp);
}
