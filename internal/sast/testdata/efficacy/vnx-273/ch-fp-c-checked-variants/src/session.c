#include <assert.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <unistd.h>

int become(uid_t uid, gid_t gid)
{
	if (setgid(gid) != 0 ||
	    setuid(uid) != 0)
		err(1, "drop");
	assert(geteuid() == uid);
	while (setgroups(0, NULL) == -1 && errno == EINTR)
		;
	return setresuid(uid, uid, uid);
}

int become2(uid_t uid)
{
	int rc =
	    setuid(uid);
	return rc;
}

int become3(uid_t uid)
{
	return
	    setuid(uid) == 0 ? 0 : -1;
}
