#include <stdio.h>
#include <string.h>
#include <unistd.h>

void names(const char *user, const char *host, int fd)
{
    char name[16];
    char path[256];
    char header[8];
    char body[512];
~>    snprintf(name, sizeof(path), "%s@%s", user, host);
~>    strncpy(name, path, sizeof path);
~>    read(fd, header, sizeof(body));
}
