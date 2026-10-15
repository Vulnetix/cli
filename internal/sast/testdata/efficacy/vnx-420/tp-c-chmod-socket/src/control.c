#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int control_listen(const char *path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
~>  chmod(path, 0777);
~>  chmod(addr.sun_path, S_IRWXU | S_IRWXG | S_IRWXO);
~>  chmod( path , 0666 );
    return listen(fd, 16);
}
