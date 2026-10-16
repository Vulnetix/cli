#include <stdlib.h>
#include <string.h>

void join(const char *a)
{
    char path[4096];
    strncpy(path, a, sizeof(path) - 1);
    path[sizeof(path) - 1] = 0;
~>    free(path);
}
