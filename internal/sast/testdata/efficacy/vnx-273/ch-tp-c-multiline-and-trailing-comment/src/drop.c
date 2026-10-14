#include <grp.h>
#include <pwd.h>
#include <unistd.h>

void drop(const struct passwd *pw, char *const argv[])
{
~>	setgroups(1, &pw->pw_gid);
~>	setresgid(pw->pw_gid,
	          pw->pw_gid,
	          pw->pw_gid);
~>	setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid); /* final */
	execv(argv[0], argv);
}
