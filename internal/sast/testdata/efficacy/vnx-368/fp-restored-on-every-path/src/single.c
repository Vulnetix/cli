#include <fcntl.h>
#include <unistd.h>

int open_device(const char *dev, uid_t user)
{
	int fd;
	if (seteuid(0) != 0)
		return -1;
	fd = open(dev, O_RDWR);
	if (seteuid(user) != 0)
		return -1;
	return fd;
}
