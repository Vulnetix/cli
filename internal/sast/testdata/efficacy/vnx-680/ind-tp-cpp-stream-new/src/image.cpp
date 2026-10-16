#include <cstdint>
#include <iostream>

uint8_t *load_pixels(std::istream &in)
{
    uint32_t w = 0, h = 0;
    in >> w >> h;
    if (!in)
        return nullptr;
~>    uint8_t *pixels = new uint8_t[w * h * 4];
    in.read(reinterpret_cast<char *>(pixels), 4);
    return pixels;
}
