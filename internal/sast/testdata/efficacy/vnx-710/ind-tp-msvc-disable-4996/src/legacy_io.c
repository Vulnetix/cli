#include <stdio.h>
#include <string.h>

~>#pragma warning(disable: 4996)

void copy_name(char *dst, const char *src)
{
    strcpy(dst, src);
}

FILE *open_log(const char *path)
{
    return fopen(path, "a");
}
