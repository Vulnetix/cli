#include <filesystem>

namespace fs = std::filesystem;

void strip(const fs::path &p)
{
    fs::permissions(p, fs::perms::set_uid | fs::perms::set_gid, fs::perm_options::remove);
    if ((fs::status(p).permissions() & fs::perms::set_uid) != fs::perms::none)
        throw std::runtime_error("still setuid");
}
