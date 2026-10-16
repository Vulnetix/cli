#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

void fine(FILE *log, const char *user, int code, uint64_t big, const char *path)
{
    printf("user %s failed with %d\n", user, code);
    fprintf(log, "%s\n", user);
    printf("%*d|%.*s\n", 5, code, 3, user);
    printf("%1$s %2$d %1$s\n", user, code);
    printf("big=%" PRIu64 "\n", big);
    int a;
    scanf("%d %*d", &a);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int rd = open(path, O_RDONLY);
    printf("100%% done\n");
}
