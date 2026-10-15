#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int make_lock(const char *lockfile)
{
	struct stat st;
	if (stat(lockfile, &st) == 0) {
		return -1;
	}
	return open(lockfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
}

int check_open(const char *p)
{
	struct stat st;
	int fd = open(p, O_RDONLY | O_NOFOLLOW);
	if (fd < 0 || fstat(fd, &st) != 0)
		return -1;
	return fd;
}
