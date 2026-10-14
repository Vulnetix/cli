#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

/* When the user may not enter their home directory the session is placed at
 * the filesystem root instead of being refused. */
int start_session(const struct passwd *pw)
{
~>	if (chdir(pw->pw_dir) < 0) {
		syslog(LOG_WARNING, "cannot enter %s, using /", pw->pw_dir);
		chdir("/");
	}
	return serve_files();
}

int start_anonymous(const char *home)
{
~>	if (chdir(home) != 0 && chdir("/") != 0)
		return -1;
	return serve_files();
}
