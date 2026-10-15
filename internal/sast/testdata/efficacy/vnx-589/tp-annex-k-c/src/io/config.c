#include <stdio.h>
#include <string.h>

int load(const char *path, char *dst, size_t n)
{
    FILE *fp;
~>    errno_t e = fopen_s(&fp, path, "r");
    if (e != 0)
        return -1;
~>    strcpy_s(dst, n, "default");
~>    if (sprintf_s(dst, n, "%s", path) < 0)
        return -1;
    fclose(fp);
    return 0;
}
