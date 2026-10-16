#include <string>
#include <sys/stat.h>

bool fix_permissions(const std::string &target)
{
	struct stat st;
	if (lstat(target.c_str(), &st) != 0)
		return false;
	if ((st.st_mode & 0077) == 0)
		return true;
~>	return chmod(target.c_str(), 0600) == 0;
}
