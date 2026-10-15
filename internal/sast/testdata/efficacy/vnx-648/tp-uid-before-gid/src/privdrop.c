#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

void drop_to(const char *user) {
    struct passwd *pw = getpwnam(user);
    if (pw == NULL) exit(1);
    if (setgroups(0, NULL) != 0) exit(1);
~>    if (setuid(pw->pw_uid) != 0) exit(1);
    if (setgid(pw->pw_gid) != 0) exit(1);
}
