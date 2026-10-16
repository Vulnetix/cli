#include <fstream>
#include <cstdint>

struct Rec { uint64_t id; double score; };

void dump(std::ofstream &out, const Rec &r)
{
~>    out.write(reinterpret_cast<const char *>(&r), sizeof(r));
}

uint64_t load_id(std::ifstream &in)
{
    uint64_t id;
~>    in.read(reinterpret_cast<char *>(&id), sizeof(id));
    return id;
}
