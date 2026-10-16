#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

int privsep_enter(const char *dir, const char *user)
{
	struct passwd *pw = getpwnam(user);
	if (pw == NULL)
		return -1;
	if (chroot(dir) != 0 || chdir("/") != 0)
		return -1;
	if (setgroups(0, NULL) != 0 || setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
		return -1;
	return 0;
}
