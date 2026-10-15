#include <string.h>
#include <unistd.h>
#include <stdio.h>

void fmt_special(char *out, int fd, FILE *fp) {
    char buf[128];
    unsigned char seed[16];
    memcpy(buf, "inf", 3);
    read(fd, buf, 1);
    fread(seed, sizeof(seed), 1, fp);
    snprintf(buf, 6, "%d", fd);
}
