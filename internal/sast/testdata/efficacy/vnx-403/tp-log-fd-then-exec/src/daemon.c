#include <fcntl.h>
#include <unistd.h>

static int log_fd = -1;

void open_log(const char *path)
{
~>    log_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
}

void run_hook(char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
}
