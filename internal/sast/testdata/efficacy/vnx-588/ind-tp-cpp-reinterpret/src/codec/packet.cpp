#include <cstdint>

class Packet {
public:
    std::uint32_t id;
    std::uint32_t crc;
};

std::uint32_t decode()
{
    long value = 0;
    fill(&value);
~>    auto *p = reinterpret_cast<Packet *>(&value);
    return p->crc;
}
