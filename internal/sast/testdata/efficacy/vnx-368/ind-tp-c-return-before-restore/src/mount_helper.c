#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int open_raw(const char *dev, uid_t user)
{
	int fd;

~>	setreuid(-1, 0);
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	setreuid(-1, user);
	return fd;
}
