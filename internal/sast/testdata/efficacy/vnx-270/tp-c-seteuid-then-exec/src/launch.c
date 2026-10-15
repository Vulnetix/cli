#include <unistd.h>
#include <stdlib.h>

int run_hook(uid_t uid, gid_t gid, const char *hook)
{
    if (setegid(gid) != 0 || seteuid(uid) != 0)
        return -1;
~>    execl("/bin/sh", "sh", "-c", hook, (char *)NULL);
    return -1;
}

int preview(uid_t uid, const char *file)
{
    seteuid(uid);
    char cmd[256];
    snprintf(cmd, sizeof cmd, "less %s", file);
~>    return system(cmd);
}
