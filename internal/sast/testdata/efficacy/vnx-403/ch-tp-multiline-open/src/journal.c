#include <fcntl.h>
#include <unistd.h>

struct journal j;

int journal_open(const char *path)
{
~>    j.fd = open(path,
                O_WRONLY | O_APPEND | O_CREAT,
                0600);
    return j.fd < 0 ? -1 : 0;
}

int journal_rotate(const char *cmd)
{
    char *argv[] = {"logrotate", (char *)cmd, NULL};
    return execvp("logrotate", argv);
}
