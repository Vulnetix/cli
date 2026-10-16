#include <sys/stat.h>

int hook_is_runnable(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;
    return (st.st_mode & S_IXUSR) != 0;
}
