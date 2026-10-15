#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int copy_file(const char *path, const char *dst)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return -1;
	int in = open(path, O_RDONLY);
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	(void)in;
	return out;
}
