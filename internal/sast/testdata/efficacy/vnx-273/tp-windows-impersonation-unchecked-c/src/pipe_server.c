#include <windows.h>

BOOL handle_client(HANDLE hPipe)
{
	char path[MAX_PATH];
	DWORD read = 0;

	ReadFile(hPipe, path, sizeof(path) - 1, &read, NULL);
	path[read] = '\0';
~>	ImpersonateNamedPipeClient(hPipe);
	DeleteFileA(path);
	RevertToSelf();
	return TRUE;
}

void run_as(HANDLE token)
{
~>	ImpersonateLoggedOnUser(token);
	do_user_work();
	RevertToSelf();
}
