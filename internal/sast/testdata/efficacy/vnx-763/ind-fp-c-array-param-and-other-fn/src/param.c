#include <stdlib.h>

void takes(char buf[], int n)
{
    free(buf);
}

void other(void)
{
    char path[64];
    path[0] = 0;
}

void unrelated(char *path)
{
    free(path);
}
