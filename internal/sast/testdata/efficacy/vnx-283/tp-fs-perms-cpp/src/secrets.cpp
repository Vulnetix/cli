#include <filesystem>

namespace fs = std::filesystem;

bool secrets_file_ok(const fs::path &p) {
    auto perms = fs::status(p).permissions();
~>    if ((perms & (fs::perms::group_write | fs::perms::others_write)) != fs::perms::none) {
        return false;
    }
    return true;
}
