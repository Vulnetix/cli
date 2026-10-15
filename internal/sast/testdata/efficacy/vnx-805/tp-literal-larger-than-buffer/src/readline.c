#include <stdio.h>
#include <unistd.h>

int read_name(int fd) {
    char line[64];
    char name[16];
~>    if (fgets(line, 128, stdin) == NULL)
        return -1;
~>    ssize_t n = read(fd, name, 32);
    return (int)n;
}
