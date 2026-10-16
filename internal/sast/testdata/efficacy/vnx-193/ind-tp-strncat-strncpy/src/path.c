#include <limits.h>
#include <string.h>

void build_path(const char *base, const char *user)
{
	char path[PATH_MAX];
	char label[64];

	strcpy(path, base);
	strcat(path, "/");
~>	strncat(path, user, sizeof(path));
~>	strncpy(label, user, strlen(user));
	open_path(path, label);
}
