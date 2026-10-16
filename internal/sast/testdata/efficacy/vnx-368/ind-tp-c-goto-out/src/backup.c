#include <fcntl.h>
#include <unistd.h>

int snapshot(const char *src, uid_t uid, gid_t gid)
{
	int fd = -1;

~>	setresuid(-1, 0, -1);
	fd = open(src, O_RDONLY);
	if (fd < 0)
		goto out;
	setresuid(-1, uid, -1);
	(void)gid;
out:
	return fd;
}
