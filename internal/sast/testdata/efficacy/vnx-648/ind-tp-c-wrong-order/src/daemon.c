#include <unistd.h>
#include <pwd.h>
#include <stdlib.h>

void drop(struct passwd *pw) {
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) exit(1);
~>    if (setuid(pw->pw_uid) != 0) exit(1);
    if (setgid(pw->pw_gid) != 0) exit(1);
}
