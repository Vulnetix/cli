#include <stdlib.h>
#include <unistd.h>

void drop_for_good(uid_t uid, gid_t gid)
{
	setgid(gid);
	setuid(uid);
	/* POS37-C: the drop must be permanent, so regaining root has to fail */
	if (setuid(0) != -1 || setgid(0) != -1)
		abort();
}
