#include <stdlib.h>
#include <unistd.h>

void drop_to(uid_t uid, gid_t gid)
{
	if (setgid(gid) != 0 || setuid(uid) != 0)
		abort();
	/* make sure root cannot be regained */
	if (setuid(0) != -1)
		abort();
}
