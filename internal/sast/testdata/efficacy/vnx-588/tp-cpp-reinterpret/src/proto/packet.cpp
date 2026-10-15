#include <cstdint>

struct Packet {
    std::uint32_t id;
    std::uint32_t size;
};

std::uint32_t peek()
{
    long value = 0;
~>    auto *p = reinterpret_cast<Packet *>(&value);
~>    const struct Packet *q = (const struct Packet *)&value;
    return p->id + q->size;
}
