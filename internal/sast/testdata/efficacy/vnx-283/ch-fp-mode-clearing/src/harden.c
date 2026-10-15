#include <sys/stat.h>

int drop_world_bits(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    mode_t tightened = st.st_mode & ~(S_IRWXG | S_IRWXO);
    return chmod(path, tightened);
}
