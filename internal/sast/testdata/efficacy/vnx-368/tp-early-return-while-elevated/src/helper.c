#include <fcntl.h>
#include <unistd.h>

int open_device(const char *dev, uid_t user)
{
	int fd;
~>	seteuid(0);
	fd = open(dev, O_RDWR);
	if (fd < 0)
		return -1;
	seteuid(user);
	return fd;
}
