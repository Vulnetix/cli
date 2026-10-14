#include <errno.h>
#include <error.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>

#define EXIT_CANCELED 125

void enter(const char *newroot, uid_t uid, gid_t gid)
{
	if (chroot(newroot) != 0)
		error(EXIT_CANCELED, errno, "cannot change root directory to %s", newroot);
	if (setgroups(0, NULL) != 0)
		error (EXIT_CANCELED, errno, "failed to set supplemental groups");
	if (setgid(gid))
		error(EXIT_FAILURE, errno, "failed to set group-ID");
	if (setuid(uid))
		error(1, errno, "failed to set user-ID");
	if (setuid(uid) != 0)
		errExit("setuid");
}
