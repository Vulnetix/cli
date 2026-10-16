#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

FILE *open_config(const char *cfg)
{
	struct stat st;

	if (stat(cfg, &st) != 0)
		return NULL;
	if (st.st_size > 1 << 20)
		return NULL;
	return fopen(cfg, "r");
}

int open_config_fd(const char *cfg)
{
	struct stat st;

	if (lstat(cfg, &st) != 0)
		return -1;
	return open(cfg, O_RDONLY | O_CLOEXEC);
}
