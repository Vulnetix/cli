#include <stdio.h>
#include <unistd.h>

struct vfs {
	int (*chroot)(const char *);
};

static int jail_and_drop(const char *dir, uid_t uid, gid_t gid)
{
	if (chroot(dir) == -1 || chdir("/") == -1)
		return -1;
	if (setresgid(gid, gid, gid) == -1)
		return -1;
	if (setresuid(uid, uid, uid) == -1)
		return -1;
	return 0;
}

static int virtual_root(struct vfs *fs, const char *dir)
{
	printf("chroot(%s)\n", dir);
	return fs->chroot(dir);
}
