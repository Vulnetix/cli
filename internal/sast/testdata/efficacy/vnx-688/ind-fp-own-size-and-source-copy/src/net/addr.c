#include <stdio.h>
#include <string.h>

void format_addr(const char *user, const char *host)
{
    char name[16];
    char path[256];
    char copy[256];
    snprintf(name, sizeof(name), "%s@%s", user, host);
    strncpy(path, host, sizeof path - 1);
    memcpy(copy, path, sizeof(path));
    memmove(copy, path, sizeof path);
    puts(name);
}
