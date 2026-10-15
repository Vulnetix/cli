#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

int dump_bytes(int fd, const uint8_t *data, size_t n)
{
    uint8_t marker = 0x7e;
    if (write(fd, &marker, sizeof(marker)) != 1)
        return -1;
    char tag[4] = {'D', 'U', 'M', 'P'};
    if (write(fd, tag, sizeof(tag)) != 4)
        return -1;
    return (int)write(fd, data, n);
}
