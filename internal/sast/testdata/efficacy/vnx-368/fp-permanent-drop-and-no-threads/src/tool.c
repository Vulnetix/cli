#include <unistd.h>

int drop(uid_t uid, gid_t gid)
{
	if (setgid(gid) != 0)
		return -1;
	if (setuid(uid) != 0)
		return -1;
	return 0;
}

int temp(uid_t user)
{
	if (seteuid(user) != 0)
		return -1;
	seteuid(0);
	return 0;
}
