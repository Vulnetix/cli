#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

void become(const char *user)
{
    struct passwd *pw = getpwnam(user);
    if (pw == NULL)
        errx(1, "no such user %s", user);
    if (setuid(pw->pw_uid) < 0)
        err(1, "setuid");
~>    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        warn("initgroups");
}
