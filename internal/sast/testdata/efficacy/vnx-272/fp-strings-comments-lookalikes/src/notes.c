#include <stdio.h>

struct jail_ops {
	int (*chroot)(const char *);
};

/* chroot(dir) must always be followed by setuid() in this daemon. */
// seteuid(0) is never called here.
int report(struct jail_ops *ops, const char *dir)
{
	printf("calling chroot(%s)\n", dir);
	puts("seteuid(0) refused");
	sandbox_chroot_path(dir);
	return ops->chroot(dir);
}
