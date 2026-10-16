#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int create_state(const char *state_path)
{
	struct stat st;
	int fd;

	if (stat(state_path, &st) == 0)
		return -1;
	fd = open(state_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return -1;
	}
	fchmod(fd, 0600);
	return fd;
}
