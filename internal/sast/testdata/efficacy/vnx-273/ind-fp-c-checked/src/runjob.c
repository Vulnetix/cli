#include <grp.h>
#include <stdlib.h>
#include <unistd.h>

int drop(uid_t uid, gid_t gid)
{
	int rc;
	if (setgroups(0, NULL) != 0)
		return -1;
	rc = setgid(gid);
	if (rc != 0)
		return rc;
	return setuid(uid);
}
