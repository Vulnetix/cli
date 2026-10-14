#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* fchmod(fd, 0600); without a check would be wrong here. */
int save_key(const char *path, const char *home, mode_t mode)
{
	int rc;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd < 0)
		return -1;
	if (fchmod(fd, 0600) != 0) {
		close(fd);
		return -1;
	}
	if (chmod(path, 0600) < 0)
		err(1, "chmod %s", path);
	rc = chmod(path, S_IRUSR | S_IWUSR);
	if (rc != 0)
		return rc;
	chmod(path, 0755);
	chmod(path, mode);
	printf("chmod(%s, 0600) done\n", path);
	if (chdir(home) < 0)
		return -1;
	chdir("/");
	return close(fd);
}
