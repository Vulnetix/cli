#include <spawn.h>
#include <unistd.h>

extern char **environ;

pid_t start_plugin(uid_t uid, char *const argv[])
{
    pid_t pid;
    if (::setreuid(-1, uid) == -1)
        return -1;
~>    if (posix_spawn(&pid, argv[0], nullptr, nullptr, argv, environ) != 0)
        return -1;
    return pid;
}

void open_editor(uid_t uid, char *const argv[])
{
    ::setresuid(-1, uid, -1);
~>    ::execvp(argv[0], argv);
}
