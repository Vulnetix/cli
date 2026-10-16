#include <stdlib.h>
#include <string.h>

struct user {
	char *login;
	char *home;
};

int user_set_login(struct user *u, const char *login)
{
~>	u->login = malloc(strlen(login));
	if (u->login == NULL)
		return -1;
	strcpy(u->login, login);
	return 0;
}
