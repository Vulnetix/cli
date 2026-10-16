#include <fstream>
#include <string>
#include <vector>

void persist_index(const std::vector<std::string>& keys)
{
~>    std::ofstream out("/tmp/cache.idx");
    for (const auto& k : keys) {
        out << k << '\n';
    }
}
