#include <filesystem>
#include <string>

namespace fs = std::filesystem;

void open_config(const fs::path &dir, int id)
{
~>    const char *cfg = (dir / "app.conf").string().c_str();
~>    auto *idtxt = std::to_string(id).c_str();
~>    const auto *base = dir.filename().string().data();
    load(cfg, idtxt, base);
}
