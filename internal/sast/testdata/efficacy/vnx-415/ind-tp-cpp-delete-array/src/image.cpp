#include <cstdint>

void Image::resize(int w, int h)
{
    delete[] pixels_;
    width_ = w;
    height_ = h;
    log("resized");
~>    delete[] pixels_;
    pixels_ = new uint32_t[w * h];
}
