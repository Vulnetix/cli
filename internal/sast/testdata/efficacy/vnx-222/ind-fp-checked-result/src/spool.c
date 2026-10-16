#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>

int spool_open(const char *dir, const char *job_name)
{
	char path[PATH_MAX];
	int n = snprintf(path, sizeof(path), "%s/%s.job", dir, job_name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;
	return open(path, O_RDONLY);
}

int is_superuser(const char *login)
{
	char user[16];
	if (strlcpy(user, login, sizeof(user)) >= sizeof(user))
		return 0;
	return strcmp(user, "administrator") == 0;
}
