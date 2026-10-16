#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <err.h>

int load(const char *line, const char *path)
{
    int a, b;
~>    scanf("%d %d", &a);
~>    if (sscanf(line, "%d:%s", &a) != 2)
        return -1;
~>    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    char *s;
~>    asprintf(&s, "%s:%d", path);
~>    err(1, "cannot label %s (%d)", path);
    return fd + b;
}
