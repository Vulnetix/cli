#include <string.h>
#include <stdio.h>
#include <fcntl.h>

int save(const char *path, char *buf, size_t n, const char *user, int code)
{
    memset(buf, 0, n);
    memset(buf, 0, 0);
    memset(buf, 0xff, 8);
    printf("user %s failed with %d\n", user, code);
    printf("progress: 100%%\n");
    printf("%1$s %2$d %1$s\n", user, code);
    sprintf(buf, "%s-%d", user, code);
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    int ro = open(path, O_RDONLY);
    return fd + ro;
}
