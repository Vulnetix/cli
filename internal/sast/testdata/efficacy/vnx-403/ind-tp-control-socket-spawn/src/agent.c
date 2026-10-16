#include <spawn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern char **environ;

struct agent {
    int ctrl_sock;
    pid_t helper;
};

int agent_listen(struct agent *a, const char *sock_path)
{
    struct sockaddr_un addr;

~>    a->ctrl_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (a->ctrl_sock < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (bind(a->ctrl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    return listen(a->ctrl_sock, 16);
}

int agent_spawn_helper(struct agent *a, char *const argv[])
{
    return posix_spawnp(&a->helper, argv[0], NULL, NULL, argv, environ);
}
