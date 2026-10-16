#include <stdio.h>
#include <unistd.h>

int read_line(char *line, size_t n)
{
    char dir[4096];
    if (fgets(line, (int)n, stdin) == NULL)
        return -1;
    if (getcwd(dir, sizeof dir) == NULL)
        return -1;
    return 0;
}
