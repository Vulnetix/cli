#include <unistd.h>
#include <stdio.h>

void print_cwd(void)
{
    char dir[1024];
~>    if (getwd(dir) != NULL)
        printf("%s\n", dir);
}
