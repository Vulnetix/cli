#include <stdexcept>
#include <string>
#include <unistd.h>

namespace sandbox {

void enter(const std::string &root)
{
~>	if (::chroot (root.c_str()) != 0) {
		throw std::runtime_error("chroot failed");
	}
	if (chdir("/") != 0) {
		throw std::runtime_error("chdir failed");
	}
	run_plugins();
}

} // namespace sandbox
