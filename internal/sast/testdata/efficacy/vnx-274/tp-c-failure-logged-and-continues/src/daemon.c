#include <pwd.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void become_user(const struct passwd *pw, const char *jail)
{
~>	if (chroot(jail) < 0) syslog(LOG_ERR, "chroot %s failed", jail);
~>	if (setgid(pw->pw_gid) == -1)
		fprintf(stderr, "setgid failed\n");
~>	if (setuid(pw->pw_uid) != 0) {
		perror("setuid");
	}
	serve_clients();
}

void become_quietly(uid_t uid)
{
~>	if (setresuid(uid, uid, uid)) {
	}
	serve_clients();
}
