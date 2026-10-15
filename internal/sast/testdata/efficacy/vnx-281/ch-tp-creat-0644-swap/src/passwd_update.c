#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int shadow_update(const char *shadow, const char *line)
{
    char next[4096];
    snprintf(next, sizeof next, "%s+", shadow);
    int out = creat(next, 0644);
    if (out < 0)
        return -1;
    write(out, line, strlen(line));
    close(out);
~>    if (rename(next, shadow) != 0) {
        unlink(next);
        return -1;
    }
    return 0;
}
