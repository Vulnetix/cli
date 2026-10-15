#include <grp.h>
#include <unistd.h>

void demote(int keep_groups, uid_t uid, gid_t gid)
{
	if (keep_groups)
~>		initgroups("daemon", gid);
	else
~>		setgroups(0, NULL);
	if (keep_groups) {
		log_info("keeping groups");
~>	} else setgid(gid);
~>	setuid(uid);
}
