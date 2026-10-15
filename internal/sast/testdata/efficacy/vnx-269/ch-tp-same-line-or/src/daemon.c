#include <pwd.h>
#include <unistd.h>
#include <err.h>

void become(struct passwd *pw)
{
~>    if (setuid(pw->pw_uid) < 0 || setgid(pw->pw_gid) < 0)
        err(1, "drop");
}
