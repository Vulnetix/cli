#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>

void ok(const char *user, int code, FILE *log, char *buf, size_t n, const char *line) {
    int a, b;
    char name[32];
    printf("user %s failed with %d\n", user, code);
    printf("100%% done\n");
    fprintf(log, "%s %s\n", user, name);
    snprintf(buf, n, "[%s] %*d", user, 4, code);
    printf("%-*.*s|\n", 10, 3, user);
    scanf("%d %d", &a, &b);
    sscanf(line, "%*s %d", &a);
    sscanf(line, "%[^,],%d%n", name, &a, &b);
    fscanf(log, "%31s", name);
    printf("%" PRIu64 "\n", (uint64_t)n);
    printf("%1$s %1$s\n", user);
    printf("%s\n", strerror(errno));
    printf("%d %d\n", max(a, b), code);
    int fd = open(user, O_WRONLY | O_CREAT, 0600);
    int fd2 = open(user, O_RDONLY);
    my_printf("%s %s", user);
    printf("%s %d\n",
           user, code);
}
