#include <fstream>
#include <cstdint>

struct Snapshot {
    std::uint32_t entries;
    std::int64_t created;
};

void writeSnapshot(std::ofstream &out, const Snapshot &s)
{
~>    out.write(reinterpret_cast<const char *>(&s), sizeof(s));
}

void readCount(std::ifstream &in, std::uint32_t &count)
{
~>    in.read(reinterpret_cast<char *>(&count), sizeof count);
}
