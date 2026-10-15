#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

void Journal::Compact(const fs::path &journal) {
    fs::path next = journal;
    next += ".compact";
    std::ofstream out(next, std::ios::trunc);
    for (const auto &entry : entries_) {
        out << entry << "\n";
    }
    out.close();
~>    fs::rename(next, journal);
}
