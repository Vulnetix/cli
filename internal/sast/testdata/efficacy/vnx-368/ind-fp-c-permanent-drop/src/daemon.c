#include <stdlib.h>
#include <unistd.h>

void drop_privileges(uid_t uid, gid_t gid)
{
	if (setgid(gid) != 0)
		exit(1);
	if (setuid(uid) != 0)
		exit(1);
	if (setresuid(uid, uid, uid) != 0)
		exit(1);
	/* seteuid(0) here would be a temporary switch */
	const char *msg = "never call seteuid(0) after this point";
	(void)msg;
}
