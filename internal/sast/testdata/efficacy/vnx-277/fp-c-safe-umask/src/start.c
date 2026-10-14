#include <stdio.h>
#include <sys/stat.h>
#include <windows.h>

/* umask(0) here would make every log world-writable. */
void start(mode_t mask, PACL acl)
{
	SECURITY_DESCRIPTOR sd;
	PSECURITY_DESCRIPTOR psd;
	mode_t current;

	umask(022);
	umask(077);
	umask(0027);
	umask(mask);
	current = umask(0);
	umask(current);
	printf("umask(0) refused\n");
	SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE);
	SetSecurityDescriptorDacl(&sd, FALSE, NULL, FALSE);
	ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &psd, NULL);
	ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;;GR;;;WD)", SDDL_REVISION_1, &psd, NULL);
}

int server_umask(int *saved)
{
	umask(*saved = umask(0777));
	return *saved;
}
