#include <grp.h>
#include <pwd.h>
#include <unistd.h>

int drop_to(struct passwd *pw) {
    if (setgroups(0, NULL) != 0) return -1;
    if (setgid(pw->pw_gid) != 0) return -1;
    if (setuid(pw->pw_uid) != 0) return -1;
    if (setuid(0) != -1) return -1;
    return 0;
}
