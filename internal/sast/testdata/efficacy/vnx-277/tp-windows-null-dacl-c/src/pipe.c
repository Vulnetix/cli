#include <windows.h>

HANDLE create_pipe(void)
{
	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa;

	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
~>	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;
	return CreateNamedPipeA("\\\\.\\pipe\\svc", PIPE_ACCESS_DUPLEX,
	                        PIPE_TYPE_BYTE, 1, 4096, 4096, 0, &sa);
}
