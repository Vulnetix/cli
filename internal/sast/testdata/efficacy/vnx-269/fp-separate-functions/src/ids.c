#include <unistd.h>

int set_user(uid_t uid)
{
    return setuid(uid);
}

int set_group(gid_t gid)
{
    return setgid(gid);
}
