#pragma once
#include <cstdint>

class Image {
public:
    Image(int w, int h);
    ~Image();

private:
    std::uint8_t* pixels_;
    int w_, h_;
};
