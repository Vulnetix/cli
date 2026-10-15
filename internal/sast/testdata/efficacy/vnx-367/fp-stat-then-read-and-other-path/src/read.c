#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

long size_of(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return -1;
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	fclose(f);
	return st.st_size;
}

int other(const char *a, const char *b)
{
	if (access(a, R_OK) != 0)
		return -1;
	return open(b, O_WRONLY);
}
