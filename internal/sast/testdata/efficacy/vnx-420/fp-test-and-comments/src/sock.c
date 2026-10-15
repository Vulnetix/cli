#include <sys/un.h>

void sock(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(fd, addr, len);
    /* chmod(path, 0777); was too permissive */
    // chmod(path, 0666);
    chmod(path, 0600);
}
