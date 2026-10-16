#include <string.h>

int is_admin(const char *login)
{
	char user[32];

	strncpy(user, login, sizeof(user) - 1);
	user[sizeof(user) - 1] = '\0';
	if (strlen(user) != strlen(login))
		return 0;
	return strcmp(user, "root") == 0;
}
