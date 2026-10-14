#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

extern void die(const char *fmt, ...);

int write_key(const char *path, const char *bin, const char *dir, int fd)
{
	if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
		close(fd);
		return -1;
	}
	if (chmod(path, 0600) < 0)
		die("chmod %s", path);
	if (chmod(path, S_IRUSR) != 0)
		error(EXIT_FAILURE, errno, "cannot protect %s", path);
	chmod(bin, 0755);
	int fd2 = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (chdir(dir) < 0)
		err(1, "chdir %s", dir);
	return fd2;
}
