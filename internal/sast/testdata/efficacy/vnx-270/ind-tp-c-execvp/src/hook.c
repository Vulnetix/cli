#include <pwd.h>
#include <unistd.h>

int run_hook(const struct passwd *pw, char *const argv[])
{
    if (setegid(pw->pw_gid) != 0)
        return -1;
    if (seteuid(pw->pw_uid) != 0)
        return -1;
~>    execvp(argv[0], argv);
    return -1;
}
