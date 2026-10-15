#include <stdio.h>
#include <string.h>

#define NAME_LEN 64

void safe(const char *src) {
    char line[256];
    char name[NAME_LEN];
    fgets(line, sizeof line, stdin);
    fgets(line, sizeof(line), stdin);
    strncpy(name, src, NAME_LEN);
    memset(&line, 0, sizeof line);
    snprintf(name, sizeof(name), "%s", src);
}
