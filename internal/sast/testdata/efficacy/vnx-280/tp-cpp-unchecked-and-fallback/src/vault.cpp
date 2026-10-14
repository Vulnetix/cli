#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace vault {

void seal(int fd, const std::string &dir)
{
~>	::fchmod(fd, S_IRUSR | S_IWUSR);
~>	if (::chdir(dir.c_str()) == -1) ::chdir("/");
	store();
}

} // namespace vault
