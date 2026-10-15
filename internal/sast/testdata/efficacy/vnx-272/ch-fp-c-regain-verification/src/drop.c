#include <grp.h>
#include <stdlib.h>
#include <unistd.h>

void drop_privileges(uid_t uid, gid_t gid)
{
	if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
		abort();
	/* make sure root cannot be regained */
	if (setuid(0) != -1 || seteuid(0) != -1)
		abort();
	if (!seteuid(0))
		abort();
}
