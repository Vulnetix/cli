#include <unistd.h>

int write_spool(uid_t user, const char *path) {
    uid_t saved = geteuid();
    if (seteuid(user) != 0) return -1;
    int rc = write_file(path);
    if (seteuid(saved) != 0) return -1;
    return rc;
}
