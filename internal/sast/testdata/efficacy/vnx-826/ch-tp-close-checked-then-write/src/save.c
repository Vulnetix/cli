#include <stdio.h>

int save(const char *path, const char *buf, size_t n)
{
	FILE *fp = fopen(path, "wb");
	if (fp == NULL)
		return -1;
~>	if (fclose(fp) != 0)
		perror("fclose");
	fwrite(buf, 1, n, fp);
	return 0;
}

int pipe_status(const char *cmd, char *out, int len)
{
	FILE *p = popen(cmd, "r");
~>	pclose(p);
	if (fgets(out, len, p) == NULL)
		out[0] = '\0';
	return 0;
}
