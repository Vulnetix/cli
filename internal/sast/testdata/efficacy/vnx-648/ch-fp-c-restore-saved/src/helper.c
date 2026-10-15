#include <unistd.h>

static uid_t saved_euid;
static gid_t saved_egid;

int with_root(int (*fn)(void))
{
	int rc;

	if (seteuid(saved_euid) != 0)
		return -1;
	if (setegid(saved_egid) != 0)
		return -1;
	rc = fn();
	return rc;
}
