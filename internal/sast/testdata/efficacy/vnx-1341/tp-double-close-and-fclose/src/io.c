#include <stdio.h>
#include <unistd.h>

int copy_out(int fd, FILE *log)
{
    char b[64];
    ssize_t n = read(fd, b, sizeof b);
    close(fd);
    fclose(log);
    if (n < 0) {
~>        close(fd);
~>        fclose(log);
        return -1;
    }
    return (int)n;
}
