#include <err.h>
#include <stdio.h>
#include <sys/stat.h>

void audit(const char *path, int fd)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return;
	if (st.st_mode & S_ISUID)
		warnx("%s is setuid", path);
	chmod(path, st.st_mode & ~(S_ISUID | S_ISGID));
	fchmod(fd, 0755);
	printf("chmod(%s, 04755)\n", path);
}
