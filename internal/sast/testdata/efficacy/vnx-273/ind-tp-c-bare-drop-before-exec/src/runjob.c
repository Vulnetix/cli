#include <pwd.h>
#include <unistd.h>

int run_as(const char *user, char **argv)
{
	struct passwd *pw = getpwnam(user);
	if (!pw)
		return -1;
~>	initgroups(pw->pw_name, pw->pw_gid);
~>	setgid(pw->pw_gid);
~>	setuid(pw->pw_uid);
	return execv(argv[0], argv);
}
