#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

static void drop_privileges(const struct passwd *pw)
{
    if (setgroups(0, NULL) != 0) abort();
    if (setgid(pw->pw_gid) != 0) abort();
    if (setuid(pw->pw_uid) != 0) abort();
    /* the drop must not be reversible */
    if (setuid(0) != -1) abort();
}

int start(const char *user)
{
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;
    drop_privileges(pw);
    return 0;
}
