#include <err.h>
#include <stdio.h>
#include <sys/stat.h>

int save_history(const char *path)
{
	FILE *fp = fopen(path, "w");

	if (fp == NULL)
		return -1;
~>	if (fchmod(fileno(fp), 0600) < 0)
		warn("fchmod %s", path);
	fputs("history\n", fp);
	return fclose(fp);
}
