#include <sys/types.h>
#include <unistd.h>

void become_nobody(uid_t uid, gid_t gid)
{
~>	(void)setresgid(gid, gid, gid);
~>	(void) setresuid(uid, uid, uid);
}
