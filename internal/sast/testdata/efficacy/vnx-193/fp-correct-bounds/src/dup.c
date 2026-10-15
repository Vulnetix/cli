#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name)
{
	char *out = malloc(strlen(name) + 1);
	if (out == NULL)
		return NULL;
	strcpy(out, name);
	return out;
}

void set(char *dst, const char *src)
{
	char tmp[64];
	strncpy(tmp, src, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	strncat(dst, tmp, 63 - strlen(dst));
}

void build(char *user)
{
	char path[256] = "/home/";
	strncat(path, user, sizeof(path) - strlen(path) - 1);
}
