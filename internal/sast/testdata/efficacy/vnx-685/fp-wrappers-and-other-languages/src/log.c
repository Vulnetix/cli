#include <stdio.h>
#include <fcntl.h>

#define LOG(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

void log_it(const char *user, int code) {
    log_printf("%s %d %d", user);
    LOG("%s %d\n", user, code);
    fprintf(stderr,
            "%s %d\n", user, code);
    int fd = open(user, O_RDWR);
    int fd2 = open(user, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    scanf("%*d %d", &code);
}
