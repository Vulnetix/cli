#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

void become(const struct passwd *pw)
{
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) err(1, "initgroups");
    if (setgid(pw->pw_gid) != 0) err(1, "setgid");
    if (setuid(pw->pw_uid) != 0) err(1, "setuid");
    if (setgid(0) != -1) errx(1, "group root regained");
    if (setuid(0) != -1) errx(1, "root regained");
}
