#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include "privdrop.h"

void drop_privileges(const struct passwd *pw)
{
~>    chroot("/var/empty");
    chdir("/");
~>    setgroups(0, NULL);
~>    setgid(pw->pw_gid);
~>    setuid(pw->pw_uid);
}
