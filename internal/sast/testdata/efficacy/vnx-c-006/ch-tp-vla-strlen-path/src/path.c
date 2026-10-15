#include <string.h>

int has_prefix(const char *path)
{
~>	char copy[strlen(path) + 1];
	strcpy(copy, path);
	return copy[0] == '/';
}
