#include <windows.h>

void init_sd(SECURITY_DESCRIPTOR *sd, PACL acl)
{
	InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE);
	/* "D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)" */
	ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", 1, NULL, NULL);
}
