#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>

void report(const char *name, int done, int total, int width, uint64_t bytes, const char *line)
{
    printf("%s: %d of %d (100%%)\n", name, done, total);
    printf("%*d|\n", width, done);
    printf("transferred %" PRIu64 " bytes\n", bytes);
    printf("%2$s %1$s\n", name, line);
    int a;
    char key[16];
    sscanf(line, "%*s %d %15s", &a, key);
    fprintf(stderr, "%s: %d of %d\n",
            name, done, total);
}

int open_ok(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int ro = open(path, O_RDONLY);
    return fd + ro;
}
