#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

int drop(struct passwd *pw)
{
    if (setgid(pw->pw_gid) != 0)
        return -1;
    if (setuid(pw->pw_uid) != 0)
        return -1;
    if (setuid(0) != -1)   /* must fail once dropped */
        return -1;
    return 0;
}

int is_setuid(const char *p)
{
    struct stat st;
    if (stat(p, &st) != 0)
        return 0;
    return (st.st_mode & S_ISUID) != 0;
}

int full_root_then_drop(uid_t uid)
{
    setuid(0);
    rebuild_cache();
    return setuid(uid);
}
