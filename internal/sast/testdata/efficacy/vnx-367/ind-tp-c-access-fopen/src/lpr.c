#include <stdio.h>
#include <unistd.h>

int print_user_file(const char *path)
{
	FILE *fp;
	char buf[4096];
	size_t n;

	if (access(path, R_OK) != 0) {
		perror("access");
		return -1;
	}
~>	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
		fwrite(buf, 1, n, stdout);
	fclose(fp);
	return 0;
}
