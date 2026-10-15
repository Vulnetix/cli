#include <err.h>
#include <pwd.h>
#include <unistd.h>

static void drop(const struct passwd *pw)
{
~>	if (setuid(pw->pw_uid) != 0)
		err(1, "setuid");
	if (setgid(pw->pw_gid) != 0)
		err(1, "setgid");
}
