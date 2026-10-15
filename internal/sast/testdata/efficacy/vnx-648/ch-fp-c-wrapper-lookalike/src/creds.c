#include <stdio.h>

void report(struct creds *c)
{
	c->setuid(c, 1000);
	creds_setuid(c, 1000);
	setgid_cache_reset();
	printf("call setuid(uid) then setgid(gid) in the wrong order\n");
}
