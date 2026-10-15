#include <string.h>

void build(char *user)
{
	char path[256] = "/home/";
~>	strncat(path, user, sizeof(path));
~>	strncat(path, "/.config", sizeof(path) - strlen(path));
}
