#include <grp.h>
#include <unistd.h>

int drop(uid_t uid, gid_t gid)
{
    if (setgroups(0, NULL) != 0)
        return -1;
    if (setresgid(gid, gid, gid) != 0)
        return -1;
    if (setresuid(uid, uid, uid) != 0)
        return -1;
    return 0;
}

int regain_then_group(gid_t gid)
{
    if (seteuid(0) != 0)
        return -1;
    if (setegid(gid) != 0)
        return -1;
    return 0;
}
