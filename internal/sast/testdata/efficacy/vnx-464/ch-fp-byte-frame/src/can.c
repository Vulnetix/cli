#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

void send_frame(int fd, char **argv)
{
    unsigned char frame[8];
    uint8_t ctl[2];
    frame[0] = (unsigned char) strtoul(argv[1], NULL, 0);
    ctl[0] = atoi(argv[2]);
    write(fd, frame, sizeof frame);
}
