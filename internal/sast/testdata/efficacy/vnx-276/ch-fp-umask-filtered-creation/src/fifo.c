#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int make_pipe(const char *path, const char *dir)
{
	if (mkdir(dir, 0777) != 0)
		return -1;
	if (mkfifo(path, 0666) != 0)
		return -1;
	return open(path, O_RDWR | O_CREAT, 0666);
}
