#include <string.h>

int greet(const char *src)
{
    char local[40] = {0};
    strncpy(local, src, sizeof(local) - 1);
    return printf("hello %s\n", local);
}

int greet2(const char *src)
{
    char name[40];
    memset(name, 0, sizeof(name));
    strncpy(name, src, sizeof(name) - 1);
    return printf("hi %s\n", name);
}
