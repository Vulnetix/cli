#include <filesystem>
namespace fs = std::filesystem;

void harden(const fs::path &p) { fs::permissions(p, fs::perms::others_all | fs::perms::group_write, fs::perm_options::remove); }

bool exists_and_regular(const fs::path &p) { return fs::is_regular_file(p) && fs::exists(p); }
