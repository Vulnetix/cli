#include <cstdlib>
#include <cstring>

struct Packet {
    unsigned char *raw;
    std::size_t header_len;
};

void release_payload(Packet &pkt)
{
~>    std::free(pkt.raw + pkt.header_len);
}

void consume(std::size_t n)
{
    unsigned char *buf = static_cast<unsigned char *>(std::malloc(n));
    std::memset(buf, 0, n);
    buf += 8;
~>    std::free(buf);
}
