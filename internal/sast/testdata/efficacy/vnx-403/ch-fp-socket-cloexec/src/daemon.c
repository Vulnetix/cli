#include <sys/socket.h>
#include <unistd.h>

static int listen_fd = -1;

int daemon_start(void)
{
    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0)
        return -1;
    return 0;
}

void run_hook(const char *script)
{
    if (fork() == 0) {
        execl("/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
}
