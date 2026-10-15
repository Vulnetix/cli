#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

int drop(struct passwd *pw)
{
    if (geteuid() != 0)
        return 0;
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
        return -1;
    return 0;
}

int is_suid(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (st.st_mode & S_ISUID) != 0;
}

int harden(const char *path, mode_t mode)
{
    return chmod(path, mode & ~(S_ISUID | S_ISGID));
}
