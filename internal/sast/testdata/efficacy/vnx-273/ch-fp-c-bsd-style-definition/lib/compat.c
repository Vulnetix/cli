#include <sys/syscall.h>
#include <unistd.h>

#ifndef HAVE_SETRESUID
int
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return syscall(SYS_setresuid, ruid, euid, suid);
}
#endif

#ifndef HAVE_SETRESGID
int
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	return syscall(SYS_setresgid, rgid, egid, sgid);
}
#endif
