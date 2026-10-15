#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

#define HDR_LEN 16
#define FRAME_MAX 64

int read_frame(int sock, FILE *log)
{
    unsigned char hdr[HDR_LEN];
    char line[32];
    char name[24];
    char path[128];

~>    if (recv(sock, hdr, FRAME_MAX, 0) <= 0)
        return -1;
~>    if (!fgets(line, 128, log))
        return -1;
~>    snprintf(name, sizeof(path), "%s/%s", "frames",
             line);
    return 0;
}
