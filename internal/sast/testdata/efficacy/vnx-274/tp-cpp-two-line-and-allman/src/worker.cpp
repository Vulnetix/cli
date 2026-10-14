#include <iostream>
#include <unistd.h>
#include <windows.h>

void drop(uid_t uid)
{
	int rc = setresuid(uid, uid, uid);
~>	if (rc != 0) {
		std::cerr << "could not drop privileges" << std::endl;
	}
	run();
}

void impersonate(HANDLE pipe)
{
~>	if (!ImpersonateNamedPipeClient(pipe))
	{
		LogWarning("impersonation failed: %lu", GetLastError());
	}
	DeleteFileW(requested_path(pipe));
	RevertToSelf();
}
