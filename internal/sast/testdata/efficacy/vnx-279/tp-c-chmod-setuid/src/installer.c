#include <stdlib.h>
#include <sys/stat.h>

int install_helper(const char *helper, const char *path, int fd)
{
	struct stat st;
	mode_t mode = 06755;

~>	chmod(helper, 04755);
	if (stat(path, &st) != 0)
		return -1;
~>	chmod(path, st.st_mode | S_ISUID);
~>	fchmod(fd, S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
~>	chmod("/usr/local/libexec/runner", mode);
~>	return system("chmod u+s /usr/local/libexec/helper");
}
