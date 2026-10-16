#include <fcntl.h>
#include <unistd.h>

int create_state_file(const char *path)
{
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    return fd;
}
