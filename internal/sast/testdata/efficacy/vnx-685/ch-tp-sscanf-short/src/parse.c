#include <stdio.h>

int parse(const char *line)
{
    int a, b, c;
~>    if (sscanf(line, "%d %d %d", &a, &b) != 3)
        return -1;
    return a + b + c;
}
