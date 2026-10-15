#include <fcntl.h>
#include <unistd.h>

int create_store(const char *path, int dirfd)
{
~>	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
	if (fd < 0)
		return -1;
~>	int fd2 = openat(dirfd, "journal", O_CREAT|O_RDWR);
	close(fd2);
	return fd;
}
