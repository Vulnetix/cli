#include <unistd.h>
#include <grp.h>
#include <stdlib.h>

void drop(uid_t uid, gid_t gid) {
    if (setgroups(0, NULL) != 0) exit(1);
    if (setgid(gid) != 0) exit(1);
    if (setuid(uid) != 0) exit(1);
    if (setuid(0) == 0) exit(1);
}
