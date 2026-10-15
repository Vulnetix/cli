#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int open_user_file(const char *base, const char *name)
{
	char path[256];
	int n = snprintf(path, sizeof(path), "%s/%s.txt", base, name);

	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;
	return open(path, O_RDONLY);
}

int remove_upload(const char *dir, const char *file)
{
	char target[128];

	if (snprintf(target, sizeof target, "%s/%s", dir, file) >= (int)sizeof target)
		return -1;
	return unlink(target);
}

int is_admin(const char *login)
{
	char user[16];

	if (strlcpy(user, login, sizeof(user)) >= sizeof(user))
		return 0;
	return strcmp(user, "administrator") == 0;
}
