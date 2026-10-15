#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int load(const char *p, size_t n)
{
    int fd = open(p, O_RDONLY);
    if (fd < 0)
        return -1;
    void *m = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED)
        return -1;
    ssize_t got = read(fd, m, n);
    if (got < 0)
        return -1;
    char *e = getenv("X");
    if (e == NULL)
        return 0;
    return 1;
}
