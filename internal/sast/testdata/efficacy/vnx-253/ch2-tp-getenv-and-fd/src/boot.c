#include <fcntl.h>
#include <stdlib.h>

int boot(void)
{
    char *home = getenv("HOME");
~>    if (home == -1)
        return 1;
    int fd = open("/dev/urandom", O_RDONLY);
~>    if (fd == NULL)
        return 2;
    return fd;
}
