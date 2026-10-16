#include <stdarg.h>
#include <stdio.h>

#define LOG_ERR(fmt, ...) my_printf("[err] " fmt, ##__VA_ARGS__)

void my_printf(const char *fmt, ...);

void handle(const char *user, int code)
{
    my_printf("user %s failed with %d\n", user);
    LOG_ERR("code %d for %s", code);
}
