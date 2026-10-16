#include <stdio.h>
#include <string.h>
#include "proto.h"

void greet(int fd, const char *user)
{
    char line[128];
    char name[32];
    int count;

    snprintf(line, sizeof line, "hello %s", user);
    memset(name, 0, sizeof name);
    read_count(fd, &count);
    printf("%s (%d) %zu\n", line, count, strlen(name));
}
