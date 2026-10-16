#include <spawn.h>
#include <unistd.h>

extern char **environ;

pid_t launch_plugin(uid_t uid, const char *path, char *const argv[])
{
    pid_t pid = -1;
    ::seteuid(uid);
~>    ::posix_spawn(&pid, path, nullptr, nullptr, argv, environ);
    return pid;
}
