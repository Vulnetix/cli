#include <pwd.h>
#include <unistd.h>

void become_spool_user(const struct passwd *pw)
{
~>	if (getuid() == 0) setgid(pw->pw_gid);
~>	if (getuid() == 0) setuid(pw->pw_uid);
	process_queue();
}
