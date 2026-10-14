#include <grp.h>
#include <unistd.h>

namespace worker {

void become(uid_t uid, gid_t gid)
{
~>	(void) setgroups(0, nullptr);
~>	(void)setresgid(gid, gid,
	                gid);
~>	setresuid(uid,
	          uid,
	          uid);
	serve_requests();
}

} // namespace worker
