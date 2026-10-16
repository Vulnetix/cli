#include <stdio.h>
#include <string.h>

FILE *open_ro(const char *path)
{
    FILE *fp = NULL;
    if (fopen_s(&fp, path, "rb") != 0) {
        return NULL;
    }
    return fp;
}

int same(const char *a, const char *b)
{
    return _stricmp(a, b) == 0;
}
