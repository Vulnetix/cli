#include <string.h>
#include <bsd/string.h>

#include "auth.h"

int is_superuser(const char *login)
{
	char user[16];

~>	strlcpy(user, login, sizeof(user));
	if (strcmp(user, "administrator") == 0)
		return 1;
	return 0;
}
