#include <stdio.h>
#include <string.h>
#include <sys/select.h>

int read_count(void)
{
    int count;
    char line[128];
    fd_set set;

    memset(line, 0, sizeof(line));
    if (scanf("%d", &count) != 1)
        return -1;
    FD_ZERO(&set);
    return count;
}

size_t copy_name(const char *src)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", src);
    return strlen(buf);
}
