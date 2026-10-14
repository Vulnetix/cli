#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <windows.h>

void drop_all(const char *user, uid_t uid, gid_t gid)
{
~>	if (initgroups(user, gid) != 0) perror("initgroups");
~>	if (setgroups(0, NULL) < 0) perror("setgroups");
~>	if (setregid(gid, gid) == -1) perror("setregid");
~>	if (setresgid(gid, gid, gid) != 0) perror("setresgid");
~>	if (setegid(gid) != 0) perror("setegid");
~>	if (seteuid(uid) != 0) perror("seteuid");
~>	if (setreuid(uid, uid) != 0) perror("setreuid");
	serve();
}

void impersonate_all(HANDLE token)
{
~>	if (!ImpersonateSelf(SecurityImpersonation)) LogError("ImpersonateSelf");
~>	if (ImpersonateAnonymousToken(GetCurrentThread()) == FALSE) LogError("anon");
~>	if (!SetThreadToken(NULL, token)) LogError("SetThreadToken");
~>	if (!ImpersonateLoggedOnUser(token)) LogError("ImpersonateLoggedOnUser");
	do_work();
}
