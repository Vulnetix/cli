#include <stdio.h>
#include <sys/stat.h>

void dump_mode(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return;
    printf("group bits: %o\n", st.st_mode & S_IRWXG);
    printf("other bits: %o\n", st.st_mode & S_IRWXO);
}
