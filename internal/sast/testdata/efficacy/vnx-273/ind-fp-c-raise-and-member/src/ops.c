#include <unistd.h>

struct priv_ops {
	int (*setuid)(uid_t);
};

void regain(struct priv_ops *ops, uid_t uid)
{
	/* setuid(uid) is called through the ops table */
	seteuid(0);
	ops->setuid(uid);
	my_setuid(uid);
}
