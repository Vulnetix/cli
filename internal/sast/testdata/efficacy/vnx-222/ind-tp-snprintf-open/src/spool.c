#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include "spool.h"

int spool_open(const struct spool *sp, const char *job_name)
{
	char path[PATH_MAX];

~>	snprintf(path, sizeof(path), "%s/%s.job", sp->dir, job_name);
	return open(path, O_RDONLY | O_CLOEXEC);
}
