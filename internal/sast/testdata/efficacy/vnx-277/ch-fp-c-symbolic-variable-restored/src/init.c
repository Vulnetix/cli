#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

struct config {
	mode_t umask;
};

int init(const struct config *cfg, const char *path)
{
	mode_t old;

	umask(S_IWGRP | S_IWOTH);
	umask(cfg->umask);
	umask(077);
	old = umask(0);
	if (mkfifo(path, 0600) != 0)
		perror("mkfifo");
	umask(old);
	printf("umask(0) disabled\n");
	return 0;
}
