#include <fcntl.h>
#include <unistd.h>

static int log_fd = -1;
static int sock = -1;

void open_log(const char *path)
{
    log_fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    audit = fopen(path, "ae");
}

void run_hook(char *const argv[])
{
    if (fork() == 0)
        execvp(argv[0], argv);
}
