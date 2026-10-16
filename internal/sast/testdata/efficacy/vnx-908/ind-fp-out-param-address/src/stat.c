#include <sys/stat.h>

long file_size(const char *p)
{
    struct stat st;
    if (stat(p, &st) == 0)
        return st.st_size;
    return -1;
}
