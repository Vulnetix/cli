#include <sys/types.h>
#include <unistd.h>

int switch_user(uid_t uid, gid_t gid)
{
    setreuid(uid, uid);
~>    setregid(gid, gid);
    return 0;
}
