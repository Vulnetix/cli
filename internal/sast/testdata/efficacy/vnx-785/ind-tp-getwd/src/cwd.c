#include <unistd.h>
#include <stdio.h>

void print_cwd(void)
{
    char dir[1024];
~>    getwd(dir);
    printf("cwd: %s\n", dir);
}
