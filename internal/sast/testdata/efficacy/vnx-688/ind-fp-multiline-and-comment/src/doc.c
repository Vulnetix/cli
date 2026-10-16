#include <stdio.h>

void explain(const char *u)
{
    char name[16];
    char path[256];
    /* snprintf(name, sizeof(path), ...) overflows name */
    // strncpy(name, path, sizeof path);
    snprintf(name,
             sizeof(path), "%s", u);
    puts("snprintf(name, sizeof(path), u)");
}
