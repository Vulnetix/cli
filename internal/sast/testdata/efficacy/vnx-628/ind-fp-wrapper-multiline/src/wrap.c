#include <stdio.h>
#include <fcntl.h>

extern void my_printf(const char *fmt, ...);
#define LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

void go(const char *a, int b)
{
    my_printf("value %s and %d\n", a);
    LOG("value %s and %d\n", a);
    int fd = open("/var/run/x.pid",
                  O_WRONLY | O_CREAT,
                  0644);
    (void)fd; (void)b;
}
