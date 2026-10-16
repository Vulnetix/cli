#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;

Credentials Credentials::from_file(const fs::path& p)
{
    const auto perms = fs::status(p).permissions();
~>    if ((perms & (fs::perms::others_read | fs::perms::group_read)) != fs::perms::none) {
        throw std::runtime_error("credentials file is readable by others: " + p.string());
    }
    std::ifstream in(p);
    return parse(in);
}
