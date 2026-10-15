#include <sys/stat.h>
#include <unistd.h>

int make_spool(const char *dir, gid_t gid) {
    if (mkdir(dir, 0770) != 0)
        return -1;
    if (chown(dir, (uid_t)-1, gid) != 0)
        return -1;
    return chmod(dir, 02770);
}
