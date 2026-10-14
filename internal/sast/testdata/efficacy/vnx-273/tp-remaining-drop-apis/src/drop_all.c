#include <grp.h>
#include <unistd.h>
#include <windows.h>
#include <rpc.h>
#include <objbase.h>

void drop_all(const char *user, uid_t uid, gid_t gid)
{
~>	initgroups(user, gid);
~>	setregid(gid, gid);
~>	setegid(gid);
~>	setreuid(uid, uid);
}

void impersonate_all(HANDLE token, RPC_BINDING_HANDLE binding)
{
~>	ImpersonateSelf(SecurityImpersonation);
~>	ImpersonateAnonymousToken(GetCurrentThread());
~>	SetThreadToken(NULL, token);
~>	RpcImpersonateClient(binding);
~>	CoImpersonateClient();
	do_work();
}
