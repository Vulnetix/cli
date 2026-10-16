#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int save_key(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || fchmod(fd, 0600) != 0)
		return -1;
	chmod("/var/www/index.html", 0644);
	return fd;
}

void enter_home(const char *dir)
{
	if (chdir(dir) != 0)
		err(1, "chdir %s", dir);
}

void daemon_root(void)
{
	chdir("/");
}

void remove_tree(const char *dir)
{
	chmod(dir, 0700);
	rmdir(dir);
}
