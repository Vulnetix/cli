#include <stdio.h>
#include <unistd.h>

void drop_user(uid_t uid)
{
    setuid(uid);
}

void drop_group(gid_t gid)
{
    printf("setuid(uid) then setgid(gid) is the wrong order\n");
    setgid(gid);
}
