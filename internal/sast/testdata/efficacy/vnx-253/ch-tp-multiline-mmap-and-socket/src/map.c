#include <sys/mman.h>
#include <sys/socket.h>

void *map_file(int fd, size_t len)
{
    void *addr = mmap(NULL, len,
                      PROT_READ, MAP_PRIVATE, fd, 0);
~>    if (addr == NULL) {
        return NULL;
    }
    return addr;
}

int listen_on(int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
~>    if (sock == NULL)
        return -1;
    return bind_port(sock, port);
}
