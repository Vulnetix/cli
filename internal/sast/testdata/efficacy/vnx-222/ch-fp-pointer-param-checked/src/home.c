#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int open_rc(void)
{
    char path[512];
    int n;

    n = snprintf(path, sizeof(path), "%s/.apprc", getenv("HOME"));
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1;
    return open(path, O_RDONLY);
}
