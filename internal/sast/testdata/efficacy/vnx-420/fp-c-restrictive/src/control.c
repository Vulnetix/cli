#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int control_listen(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    mode_t old = umask(0077);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old);
    chmod(path, 0600);
    chmod(path, 0660);
    chmod(path, S_IRUSR | S_IWUSR);
    printf("chmod(path, 0777) is unsafe\n");
    return listen(fd, 16);
}

void daemonize(void)
{
    umask(0);
    chmod(path, 0700);
}
