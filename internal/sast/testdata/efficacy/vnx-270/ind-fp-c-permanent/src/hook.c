#include <grp.h>
#include <pwd.h>
#include <unistd.h>

int run_hook(const struct passwd *pw, char *const argv[])
{
    if (setgroups(0, NULL) != 0 || setgid(pw->pw_gid) != 0)
        return -1;
    if (setuid(pw->pw_uid) != 0)
        return -1;
    execvp(argv[0], argv);
    return -1;
}
