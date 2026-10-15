#include <syslog.h>
#include <unistd.h>

void enter_jail(const char *dir)
{
	int rc = chroot(dir);
~>	if (rc != 0) {
		syslog(LOG_ERR, "chroot(%s) failed, return code %d", dir, rc);
	}
~>	if (setgid(65534) != 0)
		syslog(LOG_WARNING, "setgid failed: will exit privileged mode later");
	serve();
}
