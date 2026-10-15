#include <fcntl.h>
#include <unistd.h>

int open_privileged(const char *path)
{
	uid_t ruid = getuid();
	if (seteuid(0) != 0)
		return -1;
	int fd = open(path, O_RDONLY);
	seteuid(ruid);
	if (fd < 0)
		return -1;
	return fd;
}
