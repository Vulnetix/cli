#include <filesystem>

namespace fs = std::filesystem;

void install_helper(const fs::path& target) {
    fs::copy_file("build/helper", target, fs::copy_options::overwrite_existing);
~>    fs::permissions(target, fs::perms::set_uid | fs::perms::owner_all | fs::perms::group_exec,
                    fs::perm_options::replace);
}

void mark_group(const fs::path& target) {
~>    std::filesystem::permissions(target, std::filesystem::perms::set_gid, std::filesystem::perm_options::add);
}

void strip(const fs::path& target) {
    fs::permissions(target, fs::perms::set_uid | fs::perms::set_gid, fs::perm_options::remove);
}
