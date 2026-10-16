#include <cstdlib>

void render(size_t n)
{
    unsigned char *pixels = new unsigned char[n];
    pixels[0] = 1;
~>    free(pixels);
}
