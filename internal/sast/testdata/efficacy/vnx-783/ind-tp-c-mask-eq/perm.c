#include <sys/stat.h>

int world_writable(const struct stat *st) {
~>    if (st->st_mode & S_IWOTH == 0) {
        return 0;
    }
    return 1;
}
