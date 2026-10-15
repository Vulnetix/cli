#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int open_user_file(const char *base, const char *name)
{
	char path[256];

~>	snprintf(path, sizeof(path), "%s/%s.txt", base, name);
	return open(path, O_RDONLY);
}

int remove_upload(const char *dir, const char *file)
{
	char target[128];

~>	(void)snprintf(target, sizeof target, "%s/%s", dir, file);
	if (access(target, F_OK) != 0)
		return -1;
	return unlink(target);
}

FILE *open_report(const char *id)
{
	char buf[64];
~>	strncpy(buf, id, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
~>	strncat(buf, ".csv", sizeof(buf) - strlen(buf) - 1);
	return fopen(buf, "r");
}
