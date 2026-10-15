#include <grp.h>
#include <pwd.h>
#include <unistd.h>

int become(const struct passwd *pw)
{
    if (setgid(pw->pw_gid) < 0)
        return -1;
    if (setuid(pw->pw_uid) < 0)
        return -1;
~>    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        return -1;
    return 0;
}

int become_nobody(uid_t uid, gid_t gid)
{
    setresuid(uid, uid, uid);
~>    setgroups(0, NULL);
~>    setresgid(gid, gid, gid);
    return 0;
}
