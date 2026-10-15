#include "image.h"
#include <cstdlib>

Image::Image(int w, int h) : w_(w), h_(h) {
    pixels_ = static_cast<std::uint8_t*>(std::malloc(w * h * 4));
}

~>Image::~Image() {
    std::free(pixels_);
}
