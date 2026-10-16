#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

void enter_home(struct passwd *pw)
{
~>	if (chdir(pw->pw_dir) < 0) {
		syslog(LOG_WARNING, "cannot enter %s, using /", pw->pw_dir);
		chdir("/");
	}
}
