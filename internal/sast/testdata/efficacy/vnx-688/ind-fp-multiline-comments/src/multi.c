#include <stdio.h>

void m(const char *u)
{
    char name[16];
    char path[256];
    snprintf(name,
             sizeof(path),
             "%s", u);
    // snprintf(name, sizeof(path), "%s", u);
    const char *s = "read(fd, name, sizeof(path))";
}
