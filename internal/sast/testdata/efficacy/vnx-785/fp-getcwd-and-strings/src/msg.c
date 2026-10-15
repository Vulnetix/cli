#include <unistd.h>
#include <stdio.h>

void show(void)
{
    char dir[256];
    if (getcwd(dir, sizeof dir) != NULL)
        printf("%s\n", dir);
    puts("call getwd(buf) never; realpath(x, buf) needs PATH_MAX");
    my_getwd_wrapper();
}
