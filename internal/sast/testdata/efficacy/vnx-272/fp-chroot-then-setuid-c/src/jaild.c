#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

int enter_jail(const char *dir, const struct passwd *pw)
{
	if (chroot(dir) != 0 || chdir("/") != 0)
		return -1;
	if (setgroups(0, NULL) != 0)
		return -1;
	if (setgid(pw->pw_gid) != 0)
		return -1;
	if (setuid(pw->pw_uid) != 0)
		return -1;
	return 0;
}
