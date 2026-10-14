#include <pwd.h>
#include <unistd.h>

int privsep_become(const struct passwd *pw)
{
	if (setgid(pw->pw_gid) != 0)
		return -1;
	return setuid(pw->pw_uid);
}
