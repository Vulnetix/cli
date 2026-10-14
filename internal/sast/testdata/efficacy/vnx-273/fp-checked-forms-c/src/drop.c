#include <assert.h>
#include <err.h>
#include <grp.h>
#include <unistd.h>
#include <windows.h>

int drop_to(uid_t uid, gid_t gid)
{
	int rc;

	if (setgroups(0, NULL) != 0)
		return -1;
	if (setgid(gid) == -1)
		err(1, "setgid");
	if (setresuid(uid,
	              uid, uid) != 0)
		return -1;
	rc = seteuid(uid);
	if (rc < 0)
		return rc;
	assert(setegid(gid) == 0);
	return setuid(uid);
}

int both(uid_t uid, gid_t gid)
{
	if (setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
		return -1;
	return 0;
}

BOOL impersonate(HANDLE hPipe)
{
	if (!ImpersonateNamedPipeClient(hPipe))
		return FALSE;
	BOOL ok = ImpersonateLoggedOnUser(hPipe);
	return ok;
}
