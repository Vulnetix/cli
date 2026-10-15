#include <sys/stat.h>

int is_dir(mode_t mode)
{
~>    if (mode & S_IFMT != 0)
        return 1;
    return 0;
}
