#include <stdio.h>

int read_pair(const char *line, int *out)
{
    int a, b;
    char name[32];
~>    if (sscanf(line, "%d:%s", &a) != 2) {
        return -1;
    }
~>    scanf("%d %d", &a);
    out[0] = a;
    out[1] = b;
    (void)name;
    return 0;
}
