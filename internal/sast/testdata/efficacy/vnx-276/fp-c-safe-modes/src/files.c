#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* Never chmod(path, 0777): the installer used to do that. */
int create(const char *dir, const char *path, struct stat *st, mode_t mode)
{
	int fd;

	mkdir(dir, 0777);
	fd = open(path, O_CREAT | O_WRONLY, 0666);
	chmod(path, 0644);
	chmod(dir, 0755);
	fchmod(fd, 0600);
	chmod(path, st->st_mode & ~S_IWOTH);
	chmod("/tmp/shared", 01777);
	chmod(path, mode);
	chmod(path, 0777 & ~mode);
	umask(0777);
	printf("refusing to chmod(%s, 0777)\n", path);
	return fd;
}
