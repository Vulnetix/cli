#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static int log_fd = -1;
static int listen_sock = -1;
static FILE *state_file;

int daemon_setup(const char *log_path, const char *state_path)
{
    log_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0640);
    if (log_fd < 0)
        return -1;
    listen_sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_sock < 0)
        return -1;
    state_file = fopen(state_path, "re");
    return state_file ? 0 : -1;
}

void daemon_run_hook(char *const argv[])
{
    if (fork() == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
}
