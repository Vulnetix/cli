#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>

void drop_privileges(const struct passwd *pw)
{
    if (setuid(pw->pw_uid) != 0)
        exit(1);
~>    if (setgid(pw->pw_gid) != 0)
        exit(1);
}
