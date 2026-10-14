#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int become_user(uid_t uid, gid_t gid, const char *jail)
{
	if (chroot(jail) < 0)
		err(1, "chroot");
	if (setgid(gid) == -1) {
		perror("setgid");
		exit(1);
	}
	if (setuid(uid) != 0) {
		perror("setuid");
		return -1;
	}
	if (setgroups(0, NULL) != 0)
		goto fail;
	if (setresuid(uid, uid, uid) < 0)
		fatal("setresuid: %s", strerror(errno));
	if (seteuid(uid) != 0)
		abort();
	return 0;
fail:
	return -1;
}

void only_on_success(uid_t uid)
{
	if (setuid(uid) == 0) {
		run_unprivileged();
	}
	if (setgid(uid) != -1)
		run_unprivileged();
}
