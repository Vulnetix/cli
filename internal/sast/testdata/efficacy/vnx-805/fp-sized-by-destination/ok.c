#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LINE 64

void ok(int fd, const char *src, FILE *f) {
    char line[LINE];
    char buf[64];
    char b[64];
    fgets(line, sizeof(line), stdin);
    fgets(line, LINE, f);
    memcpy(buf, src, sizeof(buf));
    fgets(b, 64, f);
    read(fd, b, 32);
    strncpy(buf, src, sizeof buf - 1);
    snprintf(b, sizeof(b), "%s", src);
}
