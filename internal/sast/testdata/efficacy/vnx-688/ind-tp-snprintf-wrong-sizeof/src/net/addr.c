#include <stdio.h>
#include <string.h>

void format_addr(const char *user, const char *host)
{
    char name[16];
    char path[256];
~>    snprintf(name, sizeof(path), "%s@%s", user, host);
~>    strncpy(name, path, sizeof path);
    puts(name);
}
