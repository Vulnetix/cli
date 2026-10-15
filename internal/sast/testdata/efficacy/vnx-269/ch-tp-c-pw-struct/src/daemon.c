#include <grp.h>
#include <pwd.h>
#include <unistd.h>

static int become(struct passwd *pw)
{
    if (setuid(pw->pw_uid) == -1)
        return -1;
~>    if (setgid(pw->pw_gid) == -1)
        return -1;
    return 0;
}
