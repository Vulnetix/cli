#include <grp.h>
#include <unistd.h>

int switch_user(uid_t uid, gid_t gid, const char *name)
{
    if (setresuid(uid, uid, uid) != 0)
        return -1;
~>    if (initgroups(name,
                   gid) != 0)
        return -1;
~>    if (setresgid(gid, gid, gid) != 0)
        return -1;
    return 0;
}
