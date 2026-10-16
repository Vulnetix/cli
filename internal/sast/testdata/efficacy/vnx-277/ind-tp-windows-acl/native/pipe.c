#include <windows.h>
#include <sddl.h>

HANDLE make_pipe(void)
{
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
~>	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;
	return CreateNamedPipeA("\\\\.\\pipe\\acme", PIPE_ACCESS_DUPLEX, 0, 1, 4096, 4096, 0, &sa);
}

BOOL make_dir(const char *path)
{
	PSECURITY_DESCRIPTOR psd = NULL;
~>	ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &psd, NULL);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };
	return CreateDirectoryA(path, &sa);
}
