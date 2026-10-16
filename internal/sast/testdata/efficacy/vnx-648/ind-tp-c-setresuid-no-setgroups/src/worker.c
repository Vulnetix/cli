#include <err.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

void become_worker(void)
{
    struct passwd *pw = getpwnam("_worker");
    if (pw == NULL)
        errx(1, "no _worker user");
    if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
        err(1, "setresgid");
~>    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
        err(1, "setresuid");
}
