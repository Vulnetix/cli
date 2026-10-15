#include <stdio.h>
#include <string.h>
#include <unistd.h>

void show_exe(void)
{
    char target[256];
~>    ssize_t n = readlink("/proc/self/exe", target, sizeof(target));
    if (n < 0)
        return;
    printf("running %s\n", target);
}

void copy_name(char *dst, const char *src)
{
    size_t len = strlen(src);
~>    memcpy(dst, src, len);
    puts(dst);
}
