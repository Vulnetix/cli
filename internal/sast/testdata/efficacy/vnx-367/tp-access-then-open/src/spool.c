#include <fcntl.h>
#include <unistd.h>

int open_spool(const char *path)
{
	if (access(path, W_OK) != 0) {
		return -1;
	}
~>	int fd = open(path, O_WRONLY | O_APPEND);
	return fd;
}

int read_conf(const char *conf)
{
	if (access(conf, R_OK) == 0)
~>		return open(conf, O_RDONLY);
	return -1;
}
