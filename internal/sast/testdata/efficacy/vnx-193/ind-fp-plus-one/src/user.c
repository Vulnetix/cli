#include <stdlib.h>
#include <string.h>

char *dup_login(const char *login)
{
	char *out = malloc(strlen(login) + 1);
	if (out == NULL)
		return NULL;
	strcpy(out, login);
	return out;
}
