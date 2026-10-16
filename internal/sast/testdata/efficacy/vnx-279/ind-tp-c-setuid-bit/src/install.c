#include <sys/stat.h>

int install_helper(const char *helper)
{
	struct stat st;
	if (stat(helper, &st) != 0)
		return -1;
~>	if (chmod(helper, st.st_mode | S_ISUID) != 0)
		return -1;
	return 0;
}

int install_ping(const char *ping)
{
~>	return chmod(ping, 04755);
}
