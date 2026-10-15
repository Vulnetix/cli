#include <cstdint>

bool Image::decode(const uint8_t *src, size_t n)
{
    uint8_t *pixels = new uint8_t[width_ * height_ * 4];
    if (n < header_size()) {
~>        return false;
    }
    unpack(src, pixels);
    pixels_ = pixels;
    return true;
}
