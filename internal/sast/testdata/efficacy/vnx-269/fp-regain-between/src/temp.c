#include <unistd.h>

int with_user(uid_t uid, gid_t gid)
{
    seteuid(uid);
    write_user_file();
    seteuid(0);
    setegid(gid);
    seteuid(uid);
    return 0;
}

int become_root(void)
{
    setuid(0);
    setgid(0);
    return 0;
}
