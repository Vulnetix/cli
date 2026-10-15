#include <cstdint>
#include <istream>

uint8_t *load_pixels(std::istream &in) {
    uint32_t w = 0, h = 0;
    in.read(reinterpret_cast<char *>(&w), 4);
    in.read(reinterpret_cast<char *>(&h), 4);
~>    uint8_t *pixels = new uint8_t[w * h * 4];
    return pixels;
}

void *recv_block(int fd) {
    size_t items = 0;
    recv(fd, &items, sizeof(items), 0);
~>    return std::malloc(items * 16);
}
