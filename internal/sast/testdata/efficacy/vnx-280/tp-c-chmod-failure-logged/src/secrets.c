#include <stdio.h>
#include <sys/stat.h>

int write_secret(const char *path, const char *secret)
{
	FILE *f = fopen(path, "w");

	if (f == NULL)
		return -1;
~>	if (chmod(path, 0600) != 0)
		perror("chmod");
	fputs(secret, f);
	return fclose(f);
}
