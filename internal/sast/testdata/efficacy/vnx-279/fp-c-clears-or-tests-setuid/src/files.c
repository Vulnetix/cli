#include <stdio.h>
#include <sys/stat.h>

/* chmod(path, 04755) is what the old installer did. */
int harden(const char *path, const char *dir)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -1;
	if (st.st_mode & S_ISUID)
		printf("chmod 4755 found on %s\n", path);
	chmod(path, st.st_mode & ~S_ISUID);
	chmod(path, st.st_mode & ~(S_ISUID | S_ISGID));
	chmod(path, 0755);
	chmod(dir, 02775);
	chmod("/tmp/drop", 01777);
	return 0;
}
