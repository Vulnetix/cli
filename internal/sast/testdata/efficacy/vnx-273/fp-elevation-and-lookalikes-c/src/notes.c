#include <stdio.h>
#include <unistd.h>

#define DROP_TO(u) setuid(u)

extern int setuid(uid_t uid);

struct ops {
	int (*setuid)(uid_t);
};

/* setuid(uid); is done by the caller and checked there. */
// seteuid(uid);
void notes(struct ops *ops, uid_t uid)
{
	seteuid(0);
	printf("setuid(%d)\n", uid);
	my_setuid(uid);
	ops->setuid(uid);
	log_setgid_attempt(uid);
}
