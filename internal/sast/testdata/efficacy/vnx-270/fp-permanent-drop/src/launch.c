#include <grp.h>
#include <unistd.h>

int run_hook(uid_t uid, gid_t gid, const char *hook)
{
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
        return -1;
    execl("/bin/sh", "sh", "-c", hook, (char *)NULL);
    return -1;
}

int run_child(uid_t uid, char *const argv[])
{
    seteuid(uid);
    write_pidfile();
    seteuid(0);
    if (setresuid(uid, uid, uid) != 0)
        return -1;
    return execvp(argv[0], argv);
}

int run_tool(uid_t uid, const struct passwd *pw, char *const argv[])
{
    seteuid(uid);
    read_user_config();
    seteuid(0);
    drop_privileges(pw);
    return execv(argv[0], argv);
}

int run_tool2(uid_t uid, const struct passwd *pw, char *const argv[])
{
    seteuid(uid);
    dropPrivileges(pw);
    return execv(argv[0], argv);
}
