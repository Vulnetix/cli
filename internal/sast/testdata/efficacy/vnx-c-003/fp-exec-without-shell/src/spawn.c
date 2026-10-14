#include <spawn.h>
#include <unistd.h>

extern char **environ;

void spawn_ping(const char *host)
{
    char *const args[] = { "ping", "-c", "1", (char *)host, NULL };
    pid_t pid;

    if (fork() == 0) {
        execl("/usr/bin/ping", "ping", "-c", "1", host, (char *)NULL);
        _exit(127);
    }
    if (fork() == 0) {
        execvp("ping", args);
        _exit(127);
    }
    posix_spawnp(&pid, "ping", NULL, NULL, args, environ);
}
