#include <cstdlib>
#include <cstring>

struct Packet {
    unsigned char* payload;
    size_t len;

    Packet(const unsigned char* src, size_t n) : payload(static_cast<unsigned char*>(std::malloc(n))), len(n) {
        std::memcpy(payload, src, n);
    }

~>    ~Packet() {
        if (payload) {
            std::free(payload);
        }
    }
};
