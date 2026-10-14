#include <unistd.h>

static uid_t real_uid;

void privs_lower(void)
{
	real_uid = getuid();
	seteuid(real_uid);
}

void privs_regain(void)
{
	seteuid(0);
}
