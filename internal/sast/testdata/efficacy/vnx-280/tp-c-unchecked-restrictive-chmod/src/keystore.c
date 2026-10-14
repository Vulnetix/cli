#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* If the file already exists and belongs to someone else, fchmod fails with
 * EPERM and the key is written into a file other users can read. */
int save_key(const char *path, const char *key)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0)
		return -1;
~>	fchmod(fd, 0600);
	write(fd, key, strlen(key));
	return close(fd);
}

void protect(const char *token_path, const char *cfg)
{
~>	chmod(token_path, S_IRUSR | S_IWUSR);
~>	(void)chmod(cfg, 0400);
}
