#include <fcntl.h>
#include <unistd.h>

void Shell::configure()
{
    int fd = open("/etc/shell.conf", O_RDONLY);
    read_config(fd);
    close(fd);
    config_.system("reload");
}
