#include <stdio.h>
#include <sys/stat.h>

long file_size(const char *path)
{
    struct stat st;
    int n;
    if (stat(path, &st) != 0)
        return -1;
    if (sscanf(path, "%d", &n) == 1)
        return n;
    return (long)st.st_size;
}
