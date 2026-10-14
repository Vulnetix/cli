#include <err.h>
#include <errno.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

extern void fatal(const char *fmt, ...);

int demote(const char *name, uid_t uid, gid_t gid, const char *dir)
{
	if (setgid(gid) < 0)
		fatal("setgid %u: %s", (unsigned)gid, strerror(errno));
	if (setuid(uid) != 0) {
		syslog(LOG_ERR, "setuid failed");
		_exit(127);
	}
	if (initgroups(name, gid) == -1)
		err(EXIT_FAILURE, "initgroups");
	if (setuid(uid) == 0)
		syslog(LOG_INFO, "now running as %u", (unsigned)uid);
	if (chroot(dir) < 0)
		goto fail;
	return 0;
fail:
	return -1;
}
