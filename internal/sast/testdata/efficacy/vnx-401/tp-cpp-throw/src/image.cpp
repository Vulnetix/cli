Image *load_image(const char *path)
{
    unsigned char *pixels = (unsigned char *)malloc(width * height * 4);
    if (pixels == nullptr) throw std::bad_alloc();
    if (fread(pixels, 4, width * height, fp) != width * height)
~>        throw std::runtime_error("short read");
    return new Image(pixels);
}
