#include <stdlib.h>
#include <unistd.h>

void drop_permanently(uid_t uid, gid_t gid)
{
	setgid(gid);
	setuid(uid);
	if (getuid() != uid || geteuid() != uid || getegid() != gid)
		abort();
	if (setuid(0) != -1)
		abort();
}
