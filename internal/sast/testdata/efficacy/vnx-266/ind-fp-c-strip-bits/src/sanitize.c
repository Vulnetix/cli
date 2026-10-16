#include <sys/stat.h>

int strip_special_bits(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    if (st.st_mode & (S_ISUID | S_ISGID))
        return chmod(path, st.st_mode & ~(S_ISUID | S_ISGID));
    return chmod(path, 0755);
}
