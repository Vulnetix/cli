#include <filesystem>
#include <sys/stat.h>

namespace fs = std::filesystem;

void prepare(const fs::path &spool, const fs::path &out)
{
~>	fs::permissions(spool, fs::perms::all);
~>	fs::permissions(out, fs::perms::others_write, fs::perm_options::add);
~>	::chmod(out.c_str(), 0666);
}
