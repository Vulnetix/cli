#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>

void ok(char *buf, size_t n, const char *user, int code, uint64_t big)
{
    memset(buf, 0, n);
    memset(buf, 0, 0);
    printf("user %s failed with %d\n", user, code);
    printf("100%% done for %s\n", user);
    printf("%" PRIu64 " bytes\n", big);
    snprintf(buf, n, "%*d|%s", 8, code, user);
    int fd = open("/tmp/x", O_CREAT | O_WRONLY, 0600);
    (void)fd;
}
