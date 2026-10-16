#include <limits.h>
#include <string.h>

void build_path(const char *base, const char *user)
{
	char path[PATH_MAX];
	char tmp[64];
	int i;

	strncpy(path, base, sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	strncat(path, user, sizeof(path) - strlen(path) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	for (i = 0; i < 64; i++)
		tmp[i] = 0;
	open_path(path);
}
