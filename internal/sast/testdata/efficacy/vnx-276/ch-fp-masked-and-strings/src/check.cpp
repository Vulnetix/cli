#include <filesystem>
#include <stdexcept>

namespace fs = std::filesystem;

void refuse_shared(const fs::path &p)
{
    const auto st = fs::status(p);
    if ((st.permissions() & fs::perms::others_write) != fs::perms::none)
        throw std::runtime_error("refusing a world-writable config");
    fs::permissions(p, fs::perms::others_write | fs::perms::group_write, fs::perm_options::remove);
}
