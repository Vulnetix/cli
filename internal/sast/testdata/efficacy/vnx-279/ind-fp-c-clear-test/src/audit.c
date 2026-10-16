#include <sys/stat.h>
#include <stdio.h>

int harden(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return -1;
	if (st.st_mode & S_ISUID)
		fprintf(stderr, "%s is setuid, clearing\n", path);
	return chmod(path, st.st_mode & ~S_ISUID);
}
