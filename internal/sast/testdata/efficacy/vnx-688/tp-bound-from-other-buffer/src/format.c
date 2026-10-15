#include <stdio.h>
#include <string.h>

void format(const char *user, const char *host) {
    char name[16];
    char path[256];
    char line[512];
~>    snprintf(name, sizeof(path), "%s@%s", user, host);
~>    strncpy(name, path, sizeof path);
~>    fgets(name, sizeof(line), stdin);
~>    memset(name, 0, sizeof(line));
~>    memcpy(name, path, sizeof(line));
}
