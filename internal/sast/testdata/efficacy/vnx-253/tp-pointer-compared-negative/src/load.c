#include <stdio.h>
#include <stdlib.h>

int load(const char *path, size_t n)
{
~>    if (fopen(path, "r") < 0)
        return -1;
    char *buf = malloc(n);
~>    if (buf == -1) {
        return -1;
    }
~>    if ((line = fgets(tmp, sizeof tmp, in)) < 0)
        return -1;
    return 0;
}
