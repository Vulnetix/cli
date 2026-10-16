#include <unistd.h>
#include <stdio.h>

// older code used getwd(dir) but that is gone now
void show(void)
{
    char dir[512];
    if (getcwd(dir, sizeof dir) != NULL)
        printf("%s\n", dir);
    const char *msg = "never call getwd(buf)";
    puts(msg);
}
