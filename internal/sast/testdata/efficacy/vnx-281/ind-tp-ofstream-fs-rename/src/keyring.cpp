#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace vault {

void Keyring::persist(const fs::path& target) const
{
    fs::path tmp = target;
    tmp += ".partial";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        for (const auto& entry : entries_) {
            out << entry.id << '\t' << entry.encoded_secret << '\n';
        }
        out.flush();
    }
~>    fs::rename(tmp, target);
}

}  // namespace vault
