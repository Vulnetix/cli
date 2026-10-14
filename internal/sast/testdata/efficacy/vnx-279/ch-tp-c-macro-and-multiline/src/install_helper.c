#include <fcntl.h>
#include <sys/stat.h>

#define HELPER_MODE 04755

int install_helper(const char *dst)
{
~>	if (chmod(dst, HELPER_MODE) != 0)
		return -1;
~>	return fchmodat(AT_FDCWD, dst,
	                S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, 0);
}
