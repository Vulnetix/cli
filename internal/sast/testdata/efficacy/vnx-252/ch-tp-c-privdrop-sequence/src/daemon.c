#include <grp.h>
#include <pwd.h>
#include <unistd.h>

static void drop_privileges(const struct passwd *pw)
{
~>    setgroups(0, NULL);
~>    setgid(pw->pw_gid);
~>    setuid(pw->pw_uid);
}
