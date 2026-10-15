#include <stdio.h>
#include <unistd.h>

int load(int fd, FILE *fp) {
    char line[128];
    char packet[512];
~>    fgets(line, sizeof(line) + 1, fp);
~>    read(fd, packet, sizeof(packet)+1);
~>    snprintf(line, sizeof line + 2, "%s", "x");
~>    memset(packet, 0, sizeof(packet) + 1);
    return 0;
}
