#include <cstdint>
#include <cstdio>
#include <memory>

struct Image {
    uint32_t width;
    uint32_t height;
    uint8_t *pixels;
};

bool load_raw_rgba(const char *path, Image &img)
{
    FILE *f = std::fopen(path, "rb");
    if (!f) {
        return false;
    }
    uint32_t w = 0, h = 0;
    fread(&w, sizeof w, 1, f);
    fread(&h, sizeof h, 1, f);

~>    uint8_t *pixels = new uint8_t[w * h * 4];
    fread(pixels, 4, static_cast<size_t>(w) * h, f);
    std::fclose(f);
    img.width = w;
    img.height = h;
    img.pixels = pixels;
    return true;
}
