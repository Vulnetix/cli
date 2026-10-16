#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int copy_name(char *dst, size_t n, const char *name)
{
~>    size_t len = strlcpy(dst, name, n);
    if (len >= n) {
        return -1;
    }
~>    strlcat(dst, ".cfg", n);
    return 0;
}

FILE *open_config(const char *path)
{
    FILE *fp = NULL;
~>    errno_t e = fopen_s(&fp, path, "r");
    if (e != 0) {
        return NULL;
    }
    return fp;
}

unsigned int pick(unsigned int n)
{
~>    return arc4random_uniform(n);
}
