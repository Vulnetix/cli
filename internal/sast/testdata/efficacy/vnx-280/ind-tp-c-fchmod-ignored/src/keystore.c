#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int save_key(const char *path, const char *key)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
~>	fchmod(fd, 0600);
	write(fd, key, strlen(key));
	close(fd);
	return 0;
}

void protect(const char *path)
{
~>	(void)chmod(path, S_IRUSR | S_IWUSR);
}
