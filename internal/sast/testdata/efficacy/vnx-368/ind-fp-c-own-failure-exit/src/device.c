#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int open_device(const char *dev, uid_t user)
{
	int fd;

	if (seteuid(0) == -1) {
		perror("seteuid");
		return -1;
	}
	fd = open(dev, O_RDWR);
	seteuid(user);
	return fd;
}
