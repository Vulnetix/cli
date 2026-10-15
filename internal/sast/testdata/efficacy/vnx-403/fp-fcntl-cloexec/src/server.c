#include <fcntl.h>
#include <unistd.h>

int lfd;

void listen_on(void)
{
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(lfd, F_SETFD, FD_CLOEXEC);
}

void exec_child(char **argv)
{
    execvp(argv[0], argv);
}
