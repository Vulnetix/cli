#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int log_fd = -1;

int supervisor_open_log(const char *path)
{
~>    log_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0640);
    if (log_fd < 0) {
        perror("open log");
        return -1;
    }
    return 0;
}

void supervisor_log(const char *msg, size_t n)
{
    if (log_fd >= 0)
        (void)write(log_fd, msg, n);
}

pid_t supervisor_start_worker(char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return pid;
}
