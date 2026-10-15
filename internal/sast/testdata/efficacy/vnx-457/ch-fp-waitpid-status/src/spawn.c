#include <sys/wait.h>
#include <unistd.h>

int run_child(pid_t pid)
{
    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WEXITSTATUS(status);
}
