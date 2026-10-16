#include <unistd.h>

int pick(int fd, int quick, char *b, size_t n)
{
    if (quick) {
        close(fd);
    } else {
        n = read(fd, b, n);
    }
    /* close(fd); read(fd, b, n); */
    return (int)n;
}
