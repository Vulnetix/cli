#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

void drop_root(const struct passwd *pw)
{
    if (setgroups(0, NULL) != 0)
        abort();
    if (setgid(pw->pw_gid) != 0)
        abort();
    if (setuid(pw->pw_uid) != 0)
        abort();
    if (setuid(0) != -1)
        abort();
}
