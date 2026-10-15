#include <cstdint>
#include <fstream>

struct FileHeader {
    std::uint32_t version;
    std::uint64_t entries;
};

bool readHeader(std::ifstream &in, FileHeader &out)
{
    FileHeader hdr;
~>    in.read(reinterpret_cast<char *>(&hdr), sizeof hdr);
    if (!in)
        return false;
    out = hdr;
    return true;
}
