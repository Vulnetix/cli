#include <fcntl.h>

int mk(const char *path)
{
	int a = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	int b = open(path, O_RDONLY);
	int c = openat(AT_FDCWD, path, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	int d = open(path,
	             O_CREAT | O_WRONLY,
	             0644);
	return a + b + c + d;
}
