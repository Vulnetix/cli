#include <string.h>
#include <syslog.h>

#define MAX_USER 16

int is_admin(const char *login)
{
	char user[MAX_USER];

~>	strlcpy(user, login, sizeof(user));
	return strcmp(user, "administrator") == 0;
}

void audit(const char *login, const char *action)
{
	char entry[64];
~>	snprintf(entry, sizeof(entry), "user=%s action=%s", login, action);
	syslog(LOG_AUTH | LOG_NOTICE, "%s", entry);
}
