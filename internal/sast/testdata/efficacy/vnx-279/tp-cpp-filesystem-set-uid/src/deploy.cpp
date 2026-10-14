#include <filesystem>
#include <sys/stat.h>

namespace fs = std::filesystem;

void deploy(const fs::path &bin)
{
~>	fs::permissions(bin, fs::perms::set_uid, fs::perm_options::add);
~>	::chmod(bin.c_str(), 04711);
}
