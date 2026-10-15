#include <sys/un.h>

void test_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(fd, addr, len);
    chmod(path, 0777);
}
