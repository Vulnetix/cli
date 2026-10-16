#include <unistd.h>

void drop_user(uid_t uid)
{
    setuid(uid);
}

void drop_group(gid_t gid)
{
    setgid(gid);
}
