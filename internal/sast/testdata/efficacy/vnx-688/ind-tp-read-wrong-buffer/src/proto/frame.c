#include <unistd.h>
#include <string.h>
#include <stdio.h>

int read_frame(int fd, FILE *fp)
{
    char header[16];
    char body[4096];
    char line[64];
    char scratch[512];
~>    if (read(fd, header, sizeof(body)) < 0) {
        return -1;
    }
~>    fgets(line, sizeof(scratch), fp);
~>    memset(line, 0, sizeof(body));
    return 0;
}
