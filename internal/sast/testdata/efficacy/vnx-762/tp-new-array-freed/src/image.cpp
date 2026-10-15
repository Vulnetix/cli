#include <cstdlib>

void Image::decode(size_t n) {
    unsigned char *pixels = new unsigned char[n];
    fill(pixels, n);
~>    free(pixels);
}

void Image::decode2() {
    Widget *w = new Widget(42);
    w->draw();
~>    std::free(w);
}
