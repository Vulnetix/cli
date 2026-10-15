#include <fcntl.h>
#include <sys/stat.h>

int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

int write_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	return fd;
}
